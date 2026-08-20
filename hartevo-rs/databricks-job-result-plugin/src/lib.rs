//! Layer-1 Databricks Jobs API 2.2 read, proposal, and recording boundary.
//!
//! This crate deliberately has no HTTP client, keyring, Store, browser
//! profile, Effect authority, or Outcome authority. A host may provide a
//! recording/fake transport for deterministic tests. A future native OAuth
//! M2M transport is a separate Layer-2 change and cannot be inferred from a
//! fixture, recording, loopback, or `BLOCKED_ENV` transport.

#![deny(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
use thiserror::Error;

pub const CONTRACT_SCHEMA: &str = "hartevo.databricks-job-result/v1";
pub const CONTRACT_VERSION: &str = "databricks-job-result-layer-1/v1";
pub const SERVICE_ID: &str = "databricks.job-result.service";
pub const PROVIDER_ID: &str = "databricks.jobs.provider";
pub const MISSION_CONSUMER_ID: &str = "mission.databricks-job-result.consumer";
pub const JOBS_API_REVISION: &str = "jobs-api-2.2";
pub const JOBS_API_VERSION: &str = "2.2";
pub const MAX_TASKS: usize = 10_000;
pub const MAX_REPAIR_ATTEMPTS: usize = 1_000;
pub const MAX_PAGES: usize = 256;
pub const MAX_PAGE_TOKEN_LENGTH: usize = 512;
pub const MAX_OUTPUT_BYTES: usize = 5 * 1024 * 1024;
pub const OUTPUT_EXPIRY_SECONDS: i64 = 60 * 24 * 60 * 60;
pub const OUTPUT_EXPIRY_MILLIS: i64 = OUTPUT_EXPIRY_SECONDS * 1_000;
pub const MAX_IDENTIFIER_LENGTH: usize = 256;
pub const MAX_PARAMETER_LENGTH: usize = 4_096;

// SHA-256 of the stable descriptor
// `databricks-job-result-layer-1/v1|jobs-api-2.2|oauth-m2m|read-proposal-recording|output-5242880-expiry-5184000`,
// not of a runtime secret or generated binary. The contract root repeats it.
pub const CONTRACT_DIGEST: &str =
    "ce7c089e972c3494fa3224ec51cc6bcaa9d7ae6c4ab9ee15af4c121af312bfca";

/// A provider value which is safe to retain in metadata and fingerprints.
pub fn digest_text(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hex_digest(hasher.finalize().as_slice())
}

fn digest_parts<I, S>(parts: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<[u8]>,
{
    let mut hasher = Sha256::new();
    for part in parts {
        let bytes = part.as_ref();
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    hex_digest(hasher.finalize().as_slice())
}

fn digest_json<T: Serialize>(value: &T) -> String {
    let bytes = serde_json::to_vec(value).expect("contract values must serialize");
    digest_parts([bytes])
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut result, "{byte:02x}").expect("writing to a String cannot fail");
    }
    result
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), DatabricksError> {
    if valid_digest(value) {
        Ok(())
    } else {
        Err(DatabricksError::InvalidDigest { field })
    }
}

fn validate_text(value: &str, field: &'static str, max: usize) -> Result<(), DatabricksError> {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        Err(DatabricksError::InvalidText { field })
    } else {
        Ok(())
    }
}

fn validate_identifier(value: &str, field: &'static str) -> Result<(), DatabricksError> {
    validate_text(value, field, MAX_IDENTIFIER_LENGTH)
}

fn validate_task_key(value: &str) -> Result<(), DatabricksError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_LENGTH
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        Err(DatabricksError::InvalidTaskKey)
    } else {
        Ok(())
    }
}

fn validate_workspace_host(value: &str) -> Result<(), DatabricksError> {
    let Some(host) = value.strip_prefix("https://") else {
        return Err(DatabricksError::InvalidWorkspaceHost);
    };
    if host.is_empty()
        || host.contains('/')
        || host.contains('?')
        || host.contains('#')
        || host.contains('@')
        || host.chars().any(char::is_whitespace)
    {
        return Err(DatabricksError::InvalidWorkspaceHost);
    }
    Ok(())
}

fn validate_epoch(value: i64, field: &'static str) -> Result<(), DatabricksError> {
    if value < 0 {
        Err(DatabricksError::InvalidTimestamp { field })
    } else {
        Ok(())
    }
}

/// Layer-1 validation and projection failures. Values intentionally avoid
/// embedding arbitrary provider response text.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum DatabricksError {
    #[error("invalid text in {field}")]
    InvalidText { field: &'static str },
    #[error("invalid identifier in {field}")]
    InvalidIdentifier { field: &'static str },
    #[error("invalid digest in {field}")]
    InvalidDigest { field: &'static str },
    #[error("invalid task key")]
    InvalidTaskKey,
    #[error("invalid HTTPS workspace host")]
    InvalidWorkspaceHost,
    #[error("invalid timestamp in {field}")]
    InvalidTimestamp { field: &'static str },
    #[error("invalid scope")]
    InvalidScope,
    #[error("invalid OAuth M2M capability snapshot")]
    InvalidOAuthCapability,
    #[error("invalid or revoked SecretReference")]
    InvalidSecretReference,
    #[error("registration is revoked")]
    RegistrationRevoked,
    #[error("registration is reversed")]
    RegistrationReversed,
    #[error("registration integrity or revision drifted")]
    RegistrationDrift,
    #[error("provider scope does not match the registration")]
    ScopeMismatch,
    #[error("job identity or revision does not match the registration")]
    JobRevisionMismatch,
    #[error("job fingerprint does not match its metadata")]
    JobFingerprintMismatch,
    #[error("run evidence fingerprint does not match its metadata")]
    RunFingerprintMismatch,
    #[error("run proposal fingerprint does not match its metadata")]
    ProposalFingerprintMismatch,
    #[error("run receipt fingerprint does not match its metadata")]
    ReceiptFingerprintMismatch,
    #[error("result proposal fingerprint does not match its metadata")]
    ResultProposalFingerprintMismatch,
    #[error("run evidence expired")]
    EvidenceExpired,
    #[error("run evidence does not cover every proposed task")]
    MissingTaskEvidence,
    #[error("task output is truncated")]
    OutputTruncated,
    #[error("task output is missing, expired, or inaccessible")]
    OutputUnavailable,
    #[error("run lifecycle and result state are inconsistent")]
    LifecycleResultMismatch,
    #[error("Mission deadline would be exceeded by a retry")]
    MissionDeadlineExceeded,
    #[error("provider error: {0}")]
    Provider(#[from] DatabricksProviderError),
}

/// Provider transport failures. HTTP-like status variants are explicit so a
/// caller cannot mistake an unavailable environment for a connected account.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum DatabricksProviderError {
    #[error("provider rejected the request with 400")]
    BadRequest,
    #[error("provider rejected the request with 401")]
    Unauthorized,
    #[error("provider rejected the request with 403")]
    Forbidden,
    #[error("provider returned 404")]
    NotFound,
    #[error("provider rate limited the request")]
    RateLimited { retry_after_ms: u64 },
    #[error("provider request timed out")]
    Timeout,
    #[error("provider returned a retryable 5xx response")]
    ServerError { status: u16 },
    #[error("native environment is unavailable")]
    BlockedEnv,
    #[error("provider response was malformed")]
    MalformedResponse,
    #[error("a requested page was missing or out of sequence")]
    MissingPage,
    #[error("the provider repeated an opaque page token")]
    RepeatedPageToken,
    #[error("provider data was outside the registered scope")]
    OutOfScope,
    #[error("provider returned a duplicate task attempt")]
    DuplicateAttempt,
    #[error("run pagination exceeded the registered bound")]
    PaginationLimit,
    #[error("repair history exceeded the registered bound")]
    RepairLimit,
    #[error("task history exceeded the registered bound")]
    TaskLimit,
    #[error("provider output exceeded the 5 MiB boundary")]
    OutputLimit,
    #[error("provider transport is unavailable")]
    Unavailable,
}

impl DatabricksProviderError {
    fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::RateLimited { .. } | Self::Timeout | Self::ServerError { status: 500..=599 }
        )
    }

    fn retry_after_ms(&self, attempt: u8, default_backoff_ms: u64) -> u64 {
        match self {
            Self::RateLimited { retry_after_ms } => *retry_after_ms,
            Self::Timeout | Self::ServerError { .. } => {
                default_backoff_ms.saturating_mul(u64::from(attempt.max(1)))
            }
            _ => 0,
        }
    }
}

/// Opaque reference to an OAuth M2M credential. The reference identifier is
/// hashed on construction and is never retained, serialized, or formatted.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    reference_digest: String,
    scope_digest: String,
    credential_revision: u64,
    revoked: bool,
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl SecretReference {
    /// Construct the only accepted authentication boundary: OAuth M2M.
    pub fn oauth_m2m(
        reference_id: &str,
        scope_digest: &str,
        credential_revision: u64,
    ) -> Result<Self, DatabricksError> {
        validate_text(reference_id, "secret reference", MAX_IDENTIFIER_LENGTH)?;
        validate_digest(scope_digest, "secret scope digest")?;
        if credential_revision == 0 {
            return Err(DatabricksError::InvalidSecretReference);
        }
        Ok(Self {
            reference_digest: digest_parts([
                b"oauth-m2m-secret-reference",
                reference_id.as_bytes(),
            ]),
            scope_digest: scope_digest.to_owned(),
            credential_revision,
            revoked: false,
        })
    }

    /// Alias which makes the opaque nature explicit at call sites.
    pub fn new(
        reference_id: &str,
        scope_digest: &str,
        credential_revision: u64,
    ) -> Result<Self, DatabricksError> {
        Self::oauth_m2m(reference_id, scope_digest, credential_revision)
    }

    pub fn reference_digest(&self) -> &str {
        &self.reference_digest
    }

    pub fn scope_digest(&self) -> &str {
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
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OAuthGrantType {
    ClientCredentials,
}

/// Safe OAuth/service-principal permission metadata. No client secret, PAT,
/// bearer token, or token endpoint response can be stored here.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OAuthCapabilitySnapshot {
    pub grant_type: OAuthGrantType,
    pub permissions: BTreeSet<String>,
    pub service_principal_digest: String,
    pub capability_revision: u64,
}

impl OAuthCapabilitySnapshot {
    pub fn new(
        permissions: impl IntoIterator<Item = String>,
        service_principal_digest: &str,
        capability_revision: u64,
    ) -> Result<Self, DatabricksError> {
        validate_digest(service_principal_digest, "service principal digest")?;
        if capability_revision == 0 {
            return Err(DatabricksError::InvalidOAuthCapability);
        }
        let snapshot = Self {
            grant_type: OAuthGrantType::ClientCredentials,
            permissions: permissions.into_iter().collect(),
            service_principal_digest: service_principal_digest.to_owned(),
            capability_revision,
        };
        if snapshot
            .permissions
            .iter()
            .any(|permission| validate_text(permission, "OAuth permission", 128).is_err())
        {
            return Err(DatabricksError::InvalidOAuthCapability);
        }
        snapshot.validate()?;
        Ok(snapshot)
    }

    fn validate(&self) -> Result<(), DatabricksError> {
        if self.grant_type != OAuthGrantType::ClientCredentials
            || self.capability_revision == 0
            || !["jobs.read", "runs.read", "run-output.read"]
                .iter()
                .all(|permission| self.permissions.contains(*permission))
        {
            return Err(DatabricksError::InvalidOAuthCapability);
        }
        validate_digest(&self.service_principal_digest, "service principal digest")
    }
}

/// Exact identity and authority scope for one registered Databricks job.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DatabricksScope {
    pub account_id: String,
    pub workspace_host: String,
    pub workspace_id: String,
    pub job_id: u64,
    pub job_revision: u64,
    pub allowed_task_keys: BTreeSet<String>,
    pub cluster_id: Option<String>,
    pub sql_warehouse_id: Option<String>,
    pub run_ids: BTreeSet<u64>,
    pub attempt_ids: BTreeSet<u64>,
    pub mission_id: String,
    pub project_id: String,
    pub work_product_id: String,
    pub consent_revision: u64,
    pub policy_revision: u64,
}

impl DatabricksScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: &str,
        workspace_host: &str,
        workspace_id: &str,
        job_id: u64,
        job_revision: u64,
        allowed_task_keys: impl IntoIterator<Item = String>,
        mission_id: &str,
        project_id: &str,
        work_product_id: &str,
        consent_revision: u64,
        policy_revision: u64,
    ) -> Result<Self, DatabricksError> {
        let scope = Self {
            account_id: account_id.to_owned(),
            workspace_host: workspace_host.to_owned(),
            workspace_id: workspace_id.to_owned(),
            job_id,
            job_revision,
            allowed_task_keys: allowed_task_keys.into_iter().collect(),
            cluster_id: None,
            sql_warehouse_id: None,
            run_ids: BTreeSet::new(),
            attempt_ids: BTreeSet::new(),
            mission_id: mission_id.to_owned(),
            project_id: project_id.to_owned(),
            work_product_id: work_product_id.to_owned(),
            consent_revision,
            policy_revision,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn with_cluster_id(mut self, cluster_id: Option<String>) -> Result<Self, DatabricksError> {
        if let Some(value) = cluster_id.as_deref() {
            validate_identifier(value, "cluster id")?;
        }
        self.cluster_id = cluster_id;
        self.validate()?;
        Ok(self)
    }

    pub fn with_sql_warehouse_id(
        mut self,
        sql_warehouse_id: Option<String>,
    ) -> Result<Self, DatabricksError> {
        if let Some(value) = sql_warehouse_id.as_deref() {
            validate_identifier(value, "SQL warehouse id")?;
        }
        self.sql_warehouse_id = sql_warehouse_id;
        self.validate()?;
        Ok(self)
    }

    pub fn with_run_ids(
        mut self,
        run_ids: impl IntoIterator<Item = u64>,
    ) -> Result<Self, DatabricksError> {
        self.run_ids = run_ids.into_iter().collect();
        self.validate()?;
        Ok(self)
    }

    pub fn with_attempt_ids(
        mut self,
        attempt_ids: impl IntoIterator<Item = u64>,
    ) -> Result<Self, DatabricksError> {
        self.attempt_ids = attempt_ids.into_iter().collect();
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), DatabricksError> {
        validate_identifier(&self.account_id, "account id")?;
        validate_workspace_host(&self.workspace_host)?;
        validate_identifier(&self.workspace_id, "workspace id")?;
        validate_identifier(&self.mission_id, "mission id")?;
        validate_identifier(&self.project_id, "project id")?;
        validate_identifier(&self.work_product_id, "work product id")?;
        if self.job_id == 0
            || self.job_revision == 0
            || self.allowed_task_keys.is_empty()
            || self.consent_revision == 0
            || self.policy_revision == 0
            || self
                .allowed_task_keys
                .iter()
                .any(|key| validate_task_key(key).is_err())
            || self.run_ids.contains(&0)
            || self.attempt_ids.contains(&0)
        {
            return Err(DatabricksError::InvalidScope);
        }
        if self
            .cluster_id
            .as_deref()
            .is_some_and(|value| validate_identifier(value, "cluster id").is_err())
            || self
                .sql_warehouse_id
                .as_deref()
                .is_some_and(|value| validate_identifier(value, "SQL warehouse id").is_err())
        {
            return Err(DatabricksError::InvalidScope);
        }
        Ok(())
    }

    pub fn digest(&self) -> String {
        digest_json(self)
    }

    pub fn allows_run(&self, run_id: u64) -> bool {
        self.run_ids.contains(&run_id)
    }

    pub fn allows_attempt(&self, attempt_id: u64) -> bool {
        self.attempt_ids.is_empty() || self.attempt_ids.contains(&attempt_id)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TaskType {
    Notebook,
    PythonWheel,
    PythonScript,
    Jar,
    SparkSubmit,
    Sql,
    Pipeline,
    RunJob,
    Dbt,
    ProviderUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskSnapshot {
    pub task_key: String,
    pub depends_on: Vec<String>,
    pub task_type: TaskType,
    pub cluster_id: Option<String>,
    pub sql_warehouse_id: Option<String>,
    pub settings_digest: String,
}

impl TaskSnapshot {
    pub fn new(
        task_key: &str,
        depends_on: Vec<String>,
        task_type: TaskType,
        cluster_id: Option<String>,
        sql_warehouse_id: Option<String>,
        settings_digest: &str,
    ) -> Result<Self, DatabricksError> {
        validate_task_key(task_key)?;
        validate_digest(settings_digest, "task settings digest")?;
        if depends_on.iter().any(|key| validate_task_key(key).is_err())
            || has_duplicates(&depends_on)
        {
            return Err(DatabricksError::InvalidTaskKey);
        }
        if cluster_id
            .as_deref()
            .is_some_and(|value| validate_identifier(value, "task cluster id").is_err())
            || sql_warehouse_id
                .as_deref()
                .is_some_and(|value| validate_identifier(value, "task SQL warehouse id").is_err())
        {
            return Err(DatabricksError::InvalidScope);
        }
        Ok(Self {
            task_key: task_key.to_owned(),
            depends_on,
            task_type,
            cluster_id,
            sql_warehouse_id,
            settings_digest: settings_digest.to_owned(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JobSnapshot {
    pub job_id: u64,
    pub revision: u64,
    pub settings_digest: String,
    pub tasks: Vec<TaskSnapshot>,
    pub cluster_id: Option<String>,
    pub sql_warehouse_id: Option<String>,
    pub observed_at_ms: i64,
    pub fingerprint: String,
}

impl JobSnapshot {
    pub fn new(
        job_id: u64,
        revision: u64,
        settings_digest: &str,
        tasks: Vec<TaskSnapshot>,
        cluster_id: Option<String>,
        sql_warehouse_id: Option<String>,
        observed_at_ms: i64,
    ) -> Result<Self, DatabricksError> {
        validate_digest(settings_digest, "job settings digest")?;
        validate_epoch(observed_at_ms, "job observed time")?;
        if job_id == 0 || revision == 0 || tasks.is_empty() || tasks.len() > MAX_TASKS {
            return Err(DatabricksError::InvalidScope);
        }
        let task_keys = tasks
            .iter()
            .map(|task| task.task_key.clone())
            .collect::<Vec<_>>();
        if has_duplicates(&task_keys)
            || tasks.iter().any(|task| {
                task.depends_on
                    .iter()
                    .any(|dependency| !task_keys.iter().any(|key| key == dependency))
            })
        {
            return Err(DatabricksError::InvalidTaskKey);
        }
        if cluster_id
            .as_deref()
            .is_some_and(|value| validate_identifier(value, "job cluster id").is_err())
            || sql_warehouse_id
                .as_deref()
                .is_some_and(|value| validate_identifier(value, "job SQL warehouse id").is_err())
        {
            return Err(DatabricksError::InvalidScope);
        }
        let mut snapshot = Self {
            job_id,
            revision,
            settings_digest: settings_digest.to_owned(),
            tasks,
            cluster_id,
            sql_warehouse_id,
            observed_at_ms,
            fingerprint: String::new(),
        };
        snapshot.fingerprint = snapshot.recompute_fingerprint();
        Ok(snapshot)
    }

    pub fn recompute_fingerprint(&self) -> String {
        let mut copy = self.clone();
        copy.fingerprint.clear();
        digest_json(&copy)
    }

    pub fn verify_fingerprint(&self) -> bool {
        self.fingerprint == self.recompute_fingerprint()
    }
}

fn has_duplicates(values: &[String]) -> bool {
    let mut seen = BTreeSet::new();
    values.iter().any(|value| !seen.insert(value))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunParameter {
    pub key: String,
    pub value: ParameterValue,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum ParameterValue {
    Public(String),
    SensitiveDigest { digest: String },
}

impl RunParameter {
    pub fn public(key: &str, value: &str) -> Result<Self, DatabricksError> {
        validate_identifier(key, "parameter key")?;
        validate_text(value, "public parameter", MAX_PARAMETER_LENGTH)?;
        Ok(Self {
            key: key.to_owned(),
            value: ParameterValue::Public(value.to_owned()),
        })
    }

    /// Sensitive values enter Layer 1 only as a host-computed digest. The
    /// raw value is intentionally not accepted by the proposal model.
    pub fn sensitive_digest(key: &str, digest: &str) -> Result<Self, DatabricksError> {
        validate_identifier(key, "parameter key")?;
        validate_digest(digest, "sensitive parameter digest")?;
        Ok(Self {
            key: key.to_owned(),
            value: ParameterValue::SensitiveDigest {
                digest: digest.to_owned(),
            },
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceIdentity {
    pub source_digest: Option<String>,
    pub commit_digest: Option<String>,
    pub artifact_digest: Option<String>,
}

impl SourceIdentity {
    pub fn new(
        source_digest: Option<String>,
        commit_digest: Option<String>,
        artifact_digest: Option<String>,
    ) -> Result<Self, DatabricksError> {
        for (value, field) in [
            (source_digest.as_deref(), "source digest"),
            (commit_digest.as_deref(), "commit digest"),
            (artifact_digest.as_deref(), "artifact digest"),
        ] {
            if let Some(value) = value {
                validate_digest(value, field)?;
            }
        }
        Ok(Self {
            source_digest,
            commit_digest,
            artifact_digest,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunProposalInput {
    pub expected_task_keys: Vec<String>,
    pub parameters: Vec<RunParameter>,
    pub source: SourceIdentity,
    pub requested_at_ms: i64,
}

impl RunProposalInput {
    pub fn new(
        expected_task_keys: Vec<String>,
        parameters: Vec<RunParameter>,
        source: SourceIdentity,
        requested_at_ms: i64,
    ) -> Result<Self, DatabricksError> {
        if expected_task_keys.is_empty()
            || expected_task_keys.len() > MAX_TASKS
            || expected_task_keys
                .iter()
                .any(|key| validate_task_key(key).is_err())
            || has_duplicates(&expected_task_keys)
            || parameters.len() > MAX_PARAMETER_LENGTH
            || has_duplicates(
                &parameters
                    .iter()
                    .map(|parameter| parameter.key.clone())
                    .collect::<Vec<_>>(),
            )
        {
            return Err(DatabricksError::InvalidScope);
        }
        validate_epoch(requested_at_ms, "proposal requested time")?;
        Ok(Self {
            expected_task_keys,
            parameters,
            source,
            requested_at_ms,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProposalExecutionMode {
    ProposalOnly,
}

/// A deterministic, non-executable `run-now` request. It is never sent to
/// Databricks by this crate.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunProposal {
    pub proposal_version: String,
    pub operation: String,
    pub execution_mode: ProposalExecutionMode,
    pub job_id: u64,
    pub job_revision: u64,
    pub settings_digest: String,
    pub ordered_task_keys: Vec<String>,
    pub parameters: Vec<RunParameter>,
    pub source: SourceIdentity,
    pub mission_id: String,
    pub project_id: String,
    pub work_product_id: String,
    pub consent_revision: u64,
    pub policy_revision: u64,
    pub scope_digest: String,
    pub registration_digest: String,
    pub provider_idempotency_token: String,
    pub proposal_digest: String,
    pub evidence_status: EvidenceStatus,
    pub native: bool,
}

impl RunProposal {
    fn new(
        scope: &DatabricksScope,
        registration_digest: &str,
        job: &JobSnapshot,
        input: RunProposalInput,
    ) -> Result<Self, DatabricksError> {
        if job.job_id != scope.job_id
            || job.revision != scope.job_revision
            || !job.verify_fingerprint()
            || job.settings_digest.is_empty()
            || job.cluster_id != scope.cluster_id
            || job.sql_warehouse_id != scope.sql_warehouse_id
            || scope
                .allowed_task_keys
                .iter()
                .any(|key| !input.expected_task_keys.iter().any(|item| item == key))
            || input
                .expected_task_keys
                .iter()
                .any(|key| !scope.allowed_task_keys.contains(key))
        {
            return Err(DatabricksError::JobRevisionMismatch);
        }
        validate_digest(registration_digest, "registration digest")?;
        let mut proposal = Self {
            proposal_version: CONTRACT_VERSION.to_owned(),
            operation: "run-now".to_owned(),
            execution_mode: ProposalExecutionMode::ProposalOnly,
            job_id: job.job_id,
            job_revision: job.revision,
            settings_digest: job.settings_digest.clone(),
            ordered_task_keys: input.expected_task_keys,
            parameters: input.parameters,
            source: input.source,
            mission_id: scope.mission_id.clone(),
            project_id: scope.project_id.clone(),
            work_product_id: scope.work_product_id.clone(),
            consent_revision: scope.consent_revision,
            policy_revision: scope.policy_revision,
            scope_digest: scope.digest(),
            registration_digest: registration_digest.to_owned(),
            provider_idempotency_token: String::new(),
            proposal_digest: String::new(),
            evidence_status: EvidenceStatus::Recorded,
            native: false,
        };
        let identity_digest = proposal.recompute_digest();
        proposal.provider_idempotency_token = format!("dbx2-{}", &identity_digest[..59]);
        proposal.proposal_digest = proposal.recompute_digest();
        Ok(proposal)
    }

    pub fn recompute_digest(&self) -> String {
        let mut copy = self.clone();
        copy.provider_idempotency_token.clear();
        copy.proposal_digest.clear();
        digest_json(&copy)
    }

    pub fn verify_digest(&self) -> bool {
        self.provider_idempotency_token == self.expected_idempotency_token()
            && self.proposal_digest == self.recompute_digest()
    }

    pub fn expected_idempotency_token(&self) -> String {
        format!("dbx2-{}", &self.recompute_digest()[..59])
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RunLifecycleState {
    Queued,
    Pending,
    Running,
    Terminating,
    Terminated,
    WaitingForRetry,
    Blocked,
    Skipped,
    InternalError,
    ProviderUnknown,
}

impl RunLifecycleState {
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Terminated | Self::Skipped | Self::InternalError)
    }

    pub const fn is_waiting(&self) -> bool {
        matches!(
            self,
            Self::Queued
                | Self::Pending
                | Self::Running
                | Self::Terminating
                | Self::WaitingForRetry
                | Self::Blocked
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RunResultState {
    Success,
    Failed,
    TimedOut,
    Canceled,
    NotAvailable,
    ProviderUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RunTrigger {
    Manual,
    Scheduled,
    Continuous,
    Retry,
    Repair,
    ProviderUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunAttempt {
    pub job_id: u64,
    pub job_revision: u64,
    pub run_id: u64,
    pub original_run_id: u64,
    pub attempt_number: u32,
    pub lifecycle_state: RunLifecycleState,
    pub result_state: RunResultState,
    pub start_time_ms: Option<i64>,
    pub end_time_ms: Option<i64>,
    pub duration_ms: Option<i64>,
    pub trigger: RunTrigger,
    pub source_digest: Option<String>,
}

impl RunAttempt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        job_id: u64,
        job_revision: u64,
        run_id: u64,
        original_run_id: u64,
        attempt_number: u32,
        lifecycle_state: RunLifecycleState,
        result_state: RunResultState,
        start_time_ms: Option<i64>,
        end_time_ms: Option<i64>,
        duration_ms: Option<i64>,
        trigger: RunTrigger,
        source_digest: Option<String>,
    ) -> Result<Self, DatabricksError> {
        if job_id == 0 || job_revision == 0 || run_id == 0 || original_run_id == 0 {
            return Err(DatabricksError::InvalidScope);
        }
        validate_optional_times(start_time_ms, end_time_ms, duration_ms)?;
        if let Some(source_digest) = source_digest.as_deref() {
            validate_digest(source_digest, "run source digest")?;
        }
        Ok(Self {
            job_id,
            job_revision,
            run_id,
            original_run_id,
            attempt_number,
            lifecycle_state,
            result_state,
            start_time_ms,
            end_time_ms,
            duration_ms,
            trigger,
            source_digest,
        })
    }
}

fn validate_optional_times(
    start_time_ms: Option<i64>,
    end_time_ms: Option<i64>,
    duration_ms: Option<i64>,
) -> Result<(), DatabricksError> {
    for (value, field) in [
        (start_time_ms, "start time"),
        (end_time_ms, "end time"),
        (duration_ms, "duration"),
    ] {
        if let Some(value) = value {
            validate_epoch(value, field)?;
        }
    }
    if let (Some(start), Some(end)) = (start_time_ms, end_time_ms)
        && end < start
    {
        return Err(DatabricksError::InvalidTimestamp { field: "end time" });
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OutputAccess {
    Available,
    Expired,
    AccessLost,
    NotRequested,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OutputEvidence {
    pub digest: String,
    pub total_size_bytes: u64,
    pub captured_size_bytes: u64,
    pub truncated: bool,
    pub expires_at_ms: i64,
    pub access: OutputAccess,
}

impl OutputEvidence {
    pub fn from_metadata(
        digest: &str,
        total_size_bytes: u64,
        captured_size_bytes: u64,
        truncated: bool,
        expires_at_ms: i64,
    ) -> Result<Self, DatabricksError> {
        validate_digest(digest, "output digest")?;
        validate_epoch(expires_at_ms, "output expiry")?;
        if captured_size_bytes > MAX_OUTPUT_BYTES as u64
            || (!truncated && total_size_bytes > MAX_OUTPUT_BYTES as u64)
            || captured_size_bytes > total_size_bytes
            || (truncated && total_size_bytes <= MAX_OUTPUT_BYTES as u64)
        {
            return Err(DatabricksError::Provider(
                DatabricksProviderError::OutputLimit,
            ));
        }
        Ok(Self {
            digest: digest.to_owned(),
            total_size_bytes,
            captured_size_bytes,
            truncated,
            expires_at_ms,
            access: OutputAccess::Available,
        })
    }

    /// Hash at most the first 5 MiB. The bytes are not retained.
    pub fn from_bytes(bytes: &[u8], expires_at_ms: i64) -> Result<Self, DatabricksError> {
        let captured = bytes.len().min(MAX_OUTPUT_BYTES);
        let digest = digest_parts([&bytes[..captured]]);
        Self::from_metadata(
            &digest,
            bytes.len() as u64,
            captured as u64,
            bytes.len() > MAX_OUTPUT_BYTES,
            expires_at_ms,
        )
    }

    #[must_use]
    pub fn with_access(mut self, access: OutputAccess) -> Self {
        self.access = access;
        self
    }

    pub fn is_available_at(&self, now_ms: i64) -> bool {
        self.access == OutputAccess::Available && now_ms < self.expires_at_ms
    }

    pub fn is_complete_at(&self, now_ms: i64) -> bool {
        !self.truncated && self.is_available_at(now_ms)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskAttempt {
    pub task_key: String,
    pub task_run_id: u64,
    pub attempt_number: u32,
    pub original_attempt_run_id: u64,
    pub lifecycle_state: RunLifecycleState,
    pub result_state: RunResultState,
    pub start_time_ms: Option<i64>,
    pub end_time_ms: Option<i64>,
    pub duration_ms: Option<i64>,
    pub output: Option<OutputEvidence>,
}

impl TaskAttempt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        task_key: &str,
        task_run_id: u64,
        attempt_number: u32,
        original_attempt_run_id: u64,
        lifecycle_state: RunLifecycleState,
        result_state: RunResultState,
        start_time_ms: Option<i64>,
        end_time_ms: Option<i64>,
        duration_ms: Option<i64>,
        output: Option<OutputEvidence>,
    ) -> Result<Self, DatabricksError> {
        validate_task_key(task_key)?;
        if task_run_id == 0 || original_attempt_run_id == 0 {
            return Err(DatabricksError::InvalidScope);
        }
        validate_optional_times(start_time_ms, end_time_ms, duration_ms)?;
        Ok(Self {
            task_key: task_key.to_owned(),
            task_run_id,
            attempt_number,
            original_attempt_run_id,
            lifecycle_state,
            result_state,
            start_time_ms,
            end_time_ms,
            duration_ms,
            output,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RepairRecord {
    pub repair_id: u64,
    pub original_run_id: u64,
    pub repair_run_id: u64,
    pub repaired_task_keys: Vec<String>,
}

impl RepairRecord {
    pub fn new(
        repair_id: u64,
        original_run_id: u64,
        repair_run_id: u64,
        repaired_task_keys: Vec<String>,
    ) -> Result<Self, DatabricksError> {
        if repair_id == 0
            || original_run_id == 0
            || repair_run_id == 0
            || repaired_task_keys.is_empty()
            || has_duplicates(&repaired_task_keys)
            || repaired_task_keys
                .iter()
                .any(|key| validate_task_key(key).is_err())
        {
            return Err(DatabricksError::InvalidScope);
        }
        Ok(Self {
            repair_id,
            original_run_id,
            repair_run_id,
            repaired_task_keys,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunPage {
    pub page_token: Option<String>,
    pub next_page_token: Option<String>,
    pub run: RunAttempt,
    pub tasks: Vec<TaskAttempt>,
    pub repairs: Vec<RepairRecord>,
}

impl RunPage {
    pub fn new(
        run: RunAttempt,
        tasks: Vec<TaskAttempt>,
        repairs: Vec<RepairRecord>,
        next_page_token: Option<String>,
    ) -> Result<Self, DatabricksError> {
        let page = Self {
            page_token: None,
            next_page_token,
            run,
            tasks,
            repairs,
        };
        page.validate_shape()?;
        Ok(page)
    }

    pub fn for_page_token(mut self, page_token: Option<String>) -> Result<Self, DatabricksError> {
        self.page_token = page_token;
        self.validate_shape()?;
        Ok(self)
    }

    fn validate_shape(&self) -> Result<(), DatabricksError> {
        if self.tasks.len() > MAX_TASKS || self.repairs.len() > MAX_REPAIR_ATTEMPTS {
            return Err(DatabricksError::InvalidScope);
        }
        for token in [self.page_token.as_deref(), self.next_page_token.as_deref()]
            .into_iter()
            .flatten()
        {
            validate_text(token, "page token", MAX_PAGE_TOKEN_LENGTH)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunReadRequest {
    pub run_id: u64,
    pub now_ms: i64,
    pub mission_deadline_ms: i64,
    pub max_pages: usize,
    pub max_tasks: usize,
    pub max_repairs: usize,
}

impl RunReadRequest {
    pub fn new(
        run_id: u64,
        now_ms: i64,
        mission_deadline_ms: i64,
    ) -> Result<Self, DatabricksError> {
        let request = Self {
            run_id,
            now_ms,
            mission_deadline_ms,
            max_pages: MAX_PAGES,
            max_tasks: MAX_TASKS,
            max_repairs: MAX_REPAIR_ATTEMPTS,
        };
        request.with_bounds(MAX_PAGES, MAX_TASKS, MAX_REPAIR_ATTEMPTS)
    }

    pub fn with_bounds(
        mut self,
        max_pages: usize,
        max_tasks: usize,
        max_repairs: usize,
    ) -> Result<Self, DatabricksError> {
        if self.run_id == 0
            || self.now_ms < 0
            || self.mission_deadline_ms < self.now_ms
            || max_pages == 0
            || max_pages > MAX_PAGES
            || max_tasks == 0
            || max_tasks > MAX_TASKS
            || max_repairs > MAX_REPAIR_ATTEMPTS
        {
            return Err(DatabricksError::InvalidScope);
        }
        self.max_pages = max_pages;
        self.max_tasks = max_tasks;
        self.max_repairs = max_repairs;
        Ok(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransportProvenance {
    Recording,
    Fixture,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn is_native(self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceStatus {
    Recorded,
    BlockedEnv,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunEvidence {
    pub run: RunAttempt,
    pub tasks: Vec<TaskAttempt>,
    pub repairs: Vec<RepairRecord>,
    pub page_count: usize,
    pub pagination_complete: bool,
    pub observed_at_ms: i64,
    pub expires_at_ms: i64,
    pub provenance: TransportProvenance,
    pub evidence_status: EvidenceStatus,
    pub fingerprint: String,
}

impl RunEvidence {
    fn new(
        run: RunAttempt,
        tasks: Vec<TaskAttempt>,
        repairs: Vec<RepairRecord>,
        page_count: usize,
        observed_at_ms: i64,
        provenance: TransportProvenance,
    ) -> Result<Self, DatabricksError> {
        if page_count == 0
            || page_count > MAX_PAGES
            || tasks.len() > MAX_TASKS
            || repairs.len() > MAX_REPAIR_ATTEMPTS
        {
            return Err(DatabricksError::InvalidScope);
        }
        validate_epoch(observed_at_ms, "run observed time")?;
        let mut evidence = Self {
            run,
            tasks,
            repairs,
            page_count,
            pagination_complete: true,
            observed_at_ms,
            expires_at_ms: observed_at_ms.saturating_add(OUTPUT_EXPIRY_MILLIS),
            provenance,
            evidence_status: EvidenceStatus::Recorded,
            fingerprint: String::new(),
        };
        evidence.fingerprint = evidence.recompute_fingerprint();
        Ok(evidence)
    }

    pub fn recompute_fingerprint(&self) -> String {
        let mut copy = self.clone();
        copy.fingerprint.clear();
        digest_json(&copy)
    }

    pub fn verify_fingerprint(&self) -> bool {
        self.fingerprint == self.recompute_fingerprint()
    }

    pub fn is_expired_at(&self, now_ms: i64) -> bool {
        now_ms >= self.expires_at_ms
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RegistrationStatus {
    Active,
    Revoked,
    Reversed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DatabricksRegistrationSnapshot {
    pub plugin_version: String,
    pub contract_digest: String,
    pub adapter_revision: String,
    pub api_revision: String,
    pub oauth_capability: OAuthCapabilitySnapshot,
    pub scope: DatabricksScope,
    pub scope_digest: String,
    pub secret_reference_digest: String,
    pub credential_revision: u64,
    pub status: RegistrationStatus,
    pub registration_revision: u64,
    pub registration_digest: String,
}

/// Registration metadata is serializable only through the safe snapshot;
/// the opaque SecretReference itself is deliberately not serializable.
#[derive(Clone)]
pub struct DatabricksRegistration {
    snapshot: DatabricksRegistrationSnapshot,
    secret_reference: SecretReference,
}

impl fmt::Debug for DatabricksRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DatabricksRegistration")
            .field("snapshot", &self.snapshot)
            .field("secret_reference", &self.secret_reference)
            .finish()
    }
}

impl Serialize for DatabricksRegistration {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.snapshot.serialize(serializer)
    }
}

impl DatabricksRegistration {
    pub fn new(
        plugin_version: &str,
        contract_digest: &str,
        adapter_revision: &str,
        oauth_capability: OAuthCapabilitySnapshot,
        scope: DatabricksScope,
        secret_reference: SecretReference,
    ) -> Result<Self, DatabricksError> {
        validate_identifier(plugin_version, "plugin version")?;
        validate_digest(contract_digest, "contract digest")?;
        validate_identifier(adapter_revision, "adapter revision")?;
        scope.validate()?;
        oauth_capability.validate()?;
        if secret_reference.is_revoked()
            || secret_reference.scope_digest() != scope.digest()
            || contract_digest != CONTRACT_DIGEST
        {
            return Err(DatabricksError::RegistrationDrift);
        }
        let mut registration = Self {
            snapshot: DatabricksRegistrationSnapshot {
                plugin_version: plugin_version.to_owned(),
                contract_digest: contract_digest.to_owned(),
                adapter_revision: adapter_revision.to_owned(),
                api_revision: JOBS_API_REVISION.to_owned(),
                oauth_capability,
                scope_digest: scope.digest(),
                scope,
                secret_reference_digest: secret_reference.reference_digest().to_owned(),
                credential_revision: secret_reference.credential_revision(),
                status: RegistrationStatus::Active,
                registration_revision: 1,
                registration_digest: String::new(),
            },
            secret_reference,
        };
        registration.refresh_digest();
        Ok(registration)
    }

    pub fn snapshot(&self) -> DatabricksRegistrationSnapshot {
        self.snapshot.clone()
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn scope(&self) -> &DatabricksScope {
        &self.snapshot.scope
    }

    pub fn status(&self) -> RegistrationStatus {
        self.snapshot.status.clone()
    }

    pub fn registration_digest(&self) -> &str {
        &self.snapshot.registration_digest
    }

    pub fn is_active(&self) -> bool {
        self.snapshot.status == RegistrationStatus::Active
    }

    pub fn validate_integrity(&self) -> Result<(), DatabricksError> {
        if self.snapshot.api_revision != JOBS_API_REVISION
            || self.snapshot.contract_digest != CONTRACT_DIGEST
            || validate_identifier(&self.snapshot.plugin_version, "plugin version").is_err()
            || validate_identifier(&self.snapshot.adapter_revision, "adapter revision").is_err()
            || self.snapshot.scope.validate().is_err()
            || self.snapshot.scope_digest != self.snapshot.scope.digest()
            || self.secret_reference.scope_digest() != self.snapshot.scope_digest
            || self.secret_reference.reference_digest() != self.snapshot.secret_reference_digest
            || self.secret_reference.credential_revision() != self.snapshot.credential_revision
            || self.snapshot.oauth_capability.clone().validate().is_err()
            || (self.snapshot.status == RegistrationStatus::Active
                && self.secret_reference.is_revoked())
            || self.snapshot.registration_digest != self.recompute_digest()
        {
            return Err(DatabricksError::RegistrationDrift);
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<(), DatabricksError> {
        self.ensure_integrity_and_active()?;
        self.snapshot.status = RegistrationStatus::Revoked;
        self.snapshot.registration_revision = self.snapshot.registration_revision.saturating_add(1);
        self.secret_reference.revoke();
        self.refresh_digest();
        Ok(())
    }

    pub fn reverse(&mut self) -> Result<(), DatabricksError> {
        self.validate_integrity()?;
        if self.snapshot.status == RegistrationStatus::Reversed {
            return Ok(());
        }
        self.snapshot.status = RegistrationStatus::Reversed;
        self.snapshot.registration_revision = self.snapshot.registration_revision.saturating_add(1);
        self.secret_reference.revoke();
        self.refresh_digest();
        Ok(())
    }

    fn ensure_integrity_and_active(&self) -> Result<(), DatabricksError> {
        self.validate_integrity()?;
        match self.snapshot.status {
            RegistrationStatus::Active => Ok(()),
            RegistrationStatus::Revoked => Err(DatabricksError::RegistrationRevoked),
            RegistrationStatus::Reversed => Err(DatabricksError::RegistrationReversed),
        }
    }

    fn recompute_digest(&self) -> String {
        let mut snapshot = self.snapshot.clone();
        snapshot.registration_digest.clear();
        digest_json(&snapshot)
    }

    fn refresh_digest(&mut self) {
        self.snapshot.registration_digest = self.recompute_digest();
    }
}

/// A read-only transport seam. Implementations receive only the opaque
/// SecretReference and exact scope; they cannot receive secret bytes through
/// this API and there are no mutation methods to implement.
pub trait DatabricksJobsTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn describe_job(
        &mut self,
        scope: &DatabricksScope,
        secret_reference: &SecretReference,
    ) -> Result<JobSnapshot, DatabricksProviderError>;

    fn get_run_page(
        &mut self,
        scope: &DatabricksScope,
        secret_reference: &SecretReference,
        run_id: u64,
        page_token: Option<&str>,
    ) -> Result<RunPage, DatabricksProviderError>;

    fn get_run_output(
        &mut self,
        scope: &DatabricksScope,
        secret_reference: &SecretReference,
        run_id: u64,
        task_run_id: u64,
    ) -> Result<OutputEvidence, DatabricksProviderError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    pub max_attempts: u8,
    pub backoff_ms: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            backoff_ms: 100,
        }
    }
}

impl RetryPolicy {
    pub fn new(max_attempts: u8, backoff_ms: u64) -> Result<Self, DatabricksError> {
        if max_attempts == 0 || max_attempts > 8 {
            return Err(DatabricksError::InvalidScope);
        }
        Ok(Self {
            max_attempts,
            backoff_ms,
        })
    }
}

/// The typed Databricks provider. It can read bounded metadata and output
/// metadata through a host transport, but has no run-now/cancel/repair call.
#[derive(Debug)]
pub struct DatabricksJobsProvider<T> {
    transport: T,
    retry_policy: RetryPolicy,
}

impl<T: DatabricksJobsTransport> DatabricksJobsProvider<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            retry_policy: RetryPolicy::default(),
        }
    }

    #[must_use]
    pub fn with_retry_policy(mut self, retry_policy: RetryPolicy) -> Self {
        self.retry_policy = retry_policy;
        self
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn describe_job(
        &mut self,
        scope: &DatabricksScope,
        secret_reference: &SecretReference,
    ) -> Result<JobSnapshot, DatabricksError> {
        validate_scope_secret(scope, secret_reference)?;
        let job = self
            .transport
            .describe_job(scope, secret_reference)
            .map_err(DatabricksError::Provider)?;
        validate_job_scope(scope, &job)?;
        Ok(job)
    }

    #[allow(clippy::too_many_lines)]
    pub fn read_run_evidence(
        &mut self,
        scope: &DatabricksScope,
        secret_reference: &SecretReference,
        request: &RunReadRequest,
    ) -> Result<RunEvidence, DatabricksError> {
        validate_scope_secret(scope, secret_reference)?;
        if !scope.allows_run(request.run_id) {
            return Err(DatabricksError::ScopeMismatch);
        }
        if request.now_ms > request.mission_deadline_ms {
            return Err(DatabricksError::MissionDeadlineExceeded);
        }
        let mut page_token: Option<String> = None;
        let mut seen_tokens = BTreeSet::new();
        let mut seen_attempts = BTreeSet::new();
        let mut pages = 0_usize;
        let mut tasks = Vec::new();
        let mut repairs = Vec::new();
        let mut first_run: Option<RunAttempt> = None;

        loop {
            if pages >= request.max_pages {
                return Err(DatabricksError::Provider(
                    DatabricksProviderError::PaginationLimit,
                ));
            }
            let page = self.fetch_page_with_retries(
                scope,
                secret_reference,
                request.run_id,
                page_token.as_deref(),
                request.now_ms,
                request.mission_deadline_ms,
            )?;
            if page
                .page_token
                .as_deref()
                .is_some_and(|returned| Some(returned) != page_token.as_deref())
                || page.run.run_id != request.run_id
            {
                return Err(DatabricksError::Provider(
                    DatabricksProviderError::MissingPage,
                ));
            }
            if page.run.job_id != scope.job_id
                || page.run.job_revision != scope.job_revision
                || !scope.allows_run(page.run.original_run_id)
            {
                return Err(DatabricksError::Provider(
                    DatabricksProviderError::OutOfScope,
                ));
            }
            if let Some(existing) = &first_run {
                if existing != &page.run {
                    return Err(DatabricksError::Provider(
                        DatabricksProviderError::MalformedResponse,
                    ));
                }
            } else {
                first_run = Some(page.run.clone());
            }
            pages = pages.saturating_add(1);
            for task in page.tasks {
                if !scope.allowed_task_keys.contains(&task.task_key)
                    || !scope.allows_attempt(task.task_run_id)
                {
                    return Err(DatabricksError::Provider(
                        DatabricksProviderError::OutOfScope,
                    ));
                }
                if !seen_attempts.insert((task.task_key.clone(), task.attempt_number)) {
                    return Err(DatabricksError::Provider(
                        DatabricksProviderError::DuplicateAttempt,
                    ));
                }
                tasks.push(task);
                if tasks.len() > request.max_tasks {
                    return Err(DatabricksError::Provider(
                        DatabricksProviderError::TaskLimit,
                    ));
                }
            }
            for repair in page.repairs {
                if !repair
                    .repaired_task_keys
                    .iter()
                    .all(|key| scope.allowed_task_keys.contains(key))
                {
                    return Err(DatabricksError::Provider(
                        DatabricksProviderError::OutOfScope,
                    ));
                }
                repairs.push(repair);
                if repairs.len() > request.max_repairs {
                    return Err(DatabricksError::Provider(
                        DatabricksProviderError::RepairLimit,
                    ));
                }
            }
            match page.next_page_token {
                Some(next_page_token) => {
                    if !seen_tokens.insert(next_page_token.clone()) {
                        return Err(DatabricksError::Provider(
                            DatabricksProviderError::RepeatedPageToken,
                        ));
                    }
                    page_token = Some(next_page_token);
                }
                None => break,
            }
        }

        RunEvidence::new(
            first_run.ok_or(DatabricksError::Provider(
                DatabricksProviderError::MissingPage,
            ))?,
            tasks,
            repairs,
            pages,
            request.now_ms,
            self.provenance(),
        )
    }

    pub fn read_task_output(
        &mut self,
        scope: &DatabricksScope,
        secret_reference: &SecretReference,
        run_id: u64,
        task_run_id: u64,
    ) -> Result<OutputEvidence, DatabricksError> {
        validate_scope_secret(scope, secret_reference)?;
        if !scope.allows_run(run_id) || !scope.allows_attempt(task_run_id) {
            return Err(DatabricksError::ScopeMismatch);
        }
        let output = self
            .transport
            .get_run_output(scope, secret_reference, run_id, task_run_id)
            .map_err(DatabricksError::Provider)?;
        if output.captured_size_bytes > MAX_OUTPUT_BYTES as u64 {
            return Err(DatabricksError::Provider(
                DatabricksProviderError::OutputLimit,
            ));
        }
        Ok(output)
    }

    fn fetch_page_with_retries(
        &mut self,
        scope: &DatabricksScope,
        secret_reference: &SecretReference,
        run_id: u64,
        page_token: Option<&str>,
        now_ms: i64,
        mission_deadline_ms: i64,
    ) -> Result<RunPage, DatabricksError> {
        let mut attempt = 0_u8;
        let mut virtual_now = now_ms;
        loop {
            match self
                .transport
                .get_run_page(scope, secret_reference, run_id, page_token)
            {
                Ok(page) => return Ok(page),
                Err(error)
                    if error.is_retryable()
                        && attempt.saturating_add(1) < self.retry_policy.max_attempts =>
                {
                    attempt = attempt.saturating_add(1);
                    let delay = error.retry_after_ms(attempt, self.retry_policy.backoff_ms);
                    let delay = i64::try_from(delay).unwrap_or(i64::MAX);
                    virtual_now = virtual_now.saturating_add(delay);
                    if virtual_now > mission_deadline_ms {
                        return Err(DatabricksError::MissionDeadlineExceeded);
                    }
                }
                Err(error) => return Err(DatabricksError::Provider(error)),
            }
        }
    }
}

fn validate_scope_secret(
    scope: &DatabricksScope,
    secret_reference: &SecretReference,
) -> Result<(), DatabricksError> {
    scope.validate()?;
    if secret_reference.is_revoked() || secret_reference.scope_digest() != scope.digest() {
        return Err(DatabricksError::ScopeMismatch);
    }
    Ok(())
}

fn validate_job_scope(scope: &DatabricksScope, job: &JobSnapshot) -> Result<(), DatabricksError> {
    if !job.verify_fingerprint() {
        return Err(DatabricksError::JobFingerprintMismatch);
    }
    if job.job_id != scope.job_id
        || job.revision != scope.job_revision
        || job.cluster_id != scope.cluster_id
        || job.sql_warehouse_id != scope.sql_warehouse_id
        || job
            .tasks
            .iter()
            .any(|task| !scope.allowed_task_keys.contains(&task.task_key))
    {
        return Err(DatabricksError::JobRevisionMismatch);
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OutputDisposition {
    Complete,
    Missing,
    Truncated,
    Expired,
    AccessLost,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskResultEvidence {
    pub task_key: String,
    pub task_run_id: u64,
    pub attempt_number: u32,
    pub lifecycle_state: RunLifecycleState,
    pub result_state: RunResultState,
    pub output: Option<OutputEvidence>,
    pub output_disposition: OutputDisposition,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResultDisposition {
    Pending,
    Running,
    WaitingForRetry,
    Blocked,
    Success,
    Failed,
    TimedOut,
    Canceled,
    Skipped,
    InternalError,
    TerminalWithoutResult,
    MissingTaskEvidence,
    PartialOutput,
    OutputTruncated,
    OutputExpired,
    ProviderUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DatabricksJobResultProposal {
    pub proposal_version: String,
    pub mission_id: String,
    pub project_id: String,
    pub work_product_id: String,
    pub job_id: u64,
    pub job_revision: u64,
    pub run_id: u64,
    pub lifecycle_state: RunLifecycleState,
    pub result_state: RunResultState,
    pub disposition: ResultDisposition,
    pub tasks: Vec<TaskResultEvidence>,
    pub repairs: Vec<RepairRecord>,
    pub registration_digest: String,
    pub scope_digest: String,
    pub proposal_digest: String,
    pub evidence_digest: String,
    pub provenance: TransportProvenance,
    pub evidence_status: EvidenceStatus,
    pub expires_at_ms: i64,
    pub adoption: AdoptionDisposition,
    pub native: bool,
    pub fingerprint: String,
}

impl DatabricksJobResultProposal {
    pub fn recompute_fingerprint(&self) -> String {
        let mut copy = self.clone();
        copy.fingerprint.clear();
        digest_json(&copy)
    }

    pub fn verify_fingerprint(&self) -> bool {
        self.fingerprint == self.recompute_fingerprint()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AdoptionDisposition {
    NeverAdoptableByLayer1,
}

#[derive(Clone, Debug, Default)]
pub struct MissionDatabricksJobConsumer;

#[derive(Default)]
struct OutputSummary {
    missing: bool,
    truncated: bool,
    expired: bool,
}

impl MissionDatabricksJobConsumer {
    pub const fn new() -> Self {
        Self
    }

    /// Project provider evidence into a Mission-scoped proposal. This is a
    /// proposal only: it cannot create an Outcome or assert kernel truth.
    pub fn consume(
        &self,
        registration: &DatabricksRegistrationSnapshot,
        proposal: &RunProposal,
        evidence: &RunEvidence,
        now_ms: i64,
    ) -> Result<DatabricksJobResultProposal, DatabricksError> {
        if !proposal.verify_digest() {
            return Err(DatabricksError::ProposalFingerprintMismatch);
        }
        if !evidence.verify_fingerprint() {
            return Err(DatabricksError::RunFingerprintMismatch);
        }
        if registration.status != RegistrationStatus::Active
            || registration.registration_digest != proposal.registration_digest
            || registration.scope_digest != proposal.scope_digest
            || evidence.run.run_id == 0
            || evidence.run.job_id != proposal.job_id
            || evidence.run.job_revision != proposal.job_revision
            || !registration.scope.allows_run(evidence.run.run_id)
        {
            return Err(DatabricksError::RegistrationDrift);
        }
        validate_epoch(now_ms, "projection time")?;
        let mut tasks = Vec::with_capacity(proposal.ordered_task_keys.len());
        let mut missing_task = false;
        let mut output = OutputSummary::default();

        for task_key in &proposal.ordered_task_keys {
            let latest = evidence
                .tasks
                .iter()
                .filter(|task| &task.task_key == task_key)
                .max_by_key(|task| task.attempt_number);
            let Some(latest) = latest else {
                missing_task = true;
                continue;
            };
            let output_disposition = match latest.output.as_ref() {
                None => {
                    output.missing = true;
                    OutputDisposition::Missing
                }
                Some(evidence_output) if evidence_output.truncated => {
                    output.truncated = true;
                    OutputDisposition::Truncated
                }
                Some(evidence_output) if evidence_output.access == OutputAccess::AccessLost => {
                    output.missing = true;
                    OutputDisposition::AccessLost
                }
                Some(evidence_output) if !evidence_output.is_available_at(now_ms) => {
                    output.expired = true;
                    OutputDisposition::Expired
                }
                Some(_) => OutputDisposition::Complete,
            };
            tasks.push(TaskResultEvidence {
                task_key: latest.task_key.clone(),
                task_run_id: latest.task_run_id,
                attempt_number: latest.attempt_number,
                lifecycle_state: latest.lifecycle_state.clone(),
                result_state: latest.result_state.clone(),
                output: latest.output.clone(),
                output_disposition,
            });
        }

        let disposition = project_disposition(&evidence.run, missing_task, &output);
        let mut result = DatabricksJobResultProposal {
            proposal_version: CONTRACT_VERSION.to_owned(),
            mission_id: proposal.mission_id.clone(),
            project_id: proposal.project_id.clone(),
            work_product_id: proposal.work_product_id.clone(),
            job_id: proposal.job_id,
            job_revision: proposal.job_revision,
            run_id: evidence.run.run_id,
            lifecycle_state: evidence.run.lifecycle_state.clone(),
            result_state: evidence.run.result_state.clone(),
            disposition,
            tasks,
            repairs: evidence.repairs.clone(),
            registration_digest: registration.registration_digest.clone(),
            scope_digest: registration.scope_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: evidence.fingerprint.clone(),
            provenance: evidence.provenance.clone(),
            evidence_status: evidence.evidence_status.clone(),
            expires_at_ms: evidence.expires_at_ms,
            adoption: AdoptionDisposition::NeverAdoptableByLayer1,
            native: false,
            fingerprint: String::new(),
        };
        result.fingerprint = result.recompute_fingerprint();
        Ok(result)
    }
}

fn project_disposition(
    run: &RunAttempt,
    missing_task: bool,
    output: &OutputSummary,
) -> ResultDisposition {
    if matches!(run.lifecycle_state, RunLifecycleState::ProviderUnknown)
        || matches!(run.result_state, RunResultState::ProviderUnknown)
    {
        return ResultDisposition::ProviderUnknown;
    }
    let base = match run.lifecycle_state {
        RunLifecycleState::Queued | RunLifecycleState::Pending => ResultDisposition::Pending,
        RunLifecycleState::Running | RunLifecycleState::Terminating => ResultDisposition::Running,
        RunLifecycleState::WaitingForRetry => ResultDisposition::WaitingForRetry,
        RunLifecycleState::Blocked => ResultDisposition::Blocked,
        RunLifecycleState::Skipped => ResultDisposition::Skipped,
        RunLifecycleState::InternalError => ResultDisposition::InternalError,
        RunLifecycleState::ProviderUnknown | RunLifecycleState::Terminated => {
            match run.result_state {
                RunResultState::Success => ResultDisposition::Success,
                RunResultState::Failed => ResultDisposition::Failed,
                RunResultState::TimedOut => ResultDisposition::TimedOut,
                RunResultState::Canceled => ResultDisposition::Canceled,
                RunResultState::NotAvailable => ResultDisposition::TerminalWithoutResult,
                RunResultState::ProviderUnknown => ResultDisposition::ProviderUnknown,
            }
        }
    };
    if matches!(base, ResultDisposition::Success) {
        if missing_task {
            ResultDisposition::MissingTaskEvidence
        } else if output.truncated {
            ResultDisposition::OutputTruncated
        } else if output.expired {
            ResultDisposition::OutputExpired
        } else if output.missing {
            ResultDisposition::PartialOutput
        } else {
            base
        }
    } else {
        base
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerificationVerdict {
    VerifiedMetadata,
    PartialEvidence,
    FailedClosed,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerificationReason {
    ProposalTampered,
    EvidenceTampered,
    RegistrationDrift,
    EvidenceExpired,
    MissingTask,
    OutputMissing,
    OutputTruncated,
    OutputExpired,
    TerminalWithoutResult,
    ProviderUnknown,
    PaginationIncomplete,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerificationReport {
    pub verdict: VerificationVerdict,
    pub reasons: Vec<VerificationReason>,
    pub proposal_digest: String,
    pub evidence_digest: String,
    pub registration_digest: String,
    pub checked_at_ms: i64,
    pub native: bool,
    pub fingerprint: String,
}

impl VerificationReport {
    fn new(
        verdict: VerificationVerdict,
        reasons: Vec<VerificationReason>,
        proposal_digest: String,
        evidence_digest: String,
        registration_digest: String,
        checked_at_ms: i64,
    ) -> Self {
        let mut report = Self {
            verdict,
            reasons,
            proposal_digest,
            evidence_digest,
            registration_digest,
            checked_at_ms,
            native: false,
            fingerprint: String::new(),
        };
        report.fingerprint = report.recompute_fingerprint();
        report
    }

    pub fn recompute_fingerprint(&self) -> String {
        let mut copy = self.clone();
        copy.fingerprint.clear();
        digest_json(&copy)
    }

    pub fn verify_fingerprint(&self) -> bool {
        self.fingerprint == self.recompute_fingerprint()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReceiptStatus {
    MetadataRecorded,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunReceipt {
    pub receipt_version: String,
    pub status: ReceiptStatus,
    pub run_id: u64,
    pub proposal_digest: String,
    pub evidence_digest: String,
    pub registration_digest: String,
    pub scope_digest: String,
    pub provenance: TransportProvenance,
    pub recorded_at_ms: i64,
    pub expires_at_ms: i64,
    pub effect_applied: bool,
    pub provider_receipt: bool,
    pub native: bool,
    pub fingerprint: String,
}

impl RunReceipt {
    pub fn recompute_fingerprint(&self) -> String {
        let mut copy = self.clone();
        copy.fingerprint.clear();
        digest_json(&copy)
    }

    pub fn verify_fingerprint(&self) -> bool {
        self.fingerprint == self.recompute_fingerprint()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JobDescription {
    pub service_id: String,
    pub provider_id: String,
    pub api_revision: String,
    pub job: JobSnapshot,
    pub registration: DatabricksRegistrationSnapshot,
    pub provenance: TransportProvenance,
    pub native: bool,
}

/// The service owns registration checks and composes the typed provider and
/// Mission consumer. It has no Store/keyring/effect/Outcome dependency.
#[derive(Debug)]
pub struct DatabricksJobResultService<T> {
    provider: DatabricksJobsProvider<T>,
    registration: DatabricksRegistration,
}

impl<T: DatabricksJobsTransport> DatabricksJobResultService<T> {
    pub fn new(
        provider: DatabricksJobsProvider<T>,
        registration: DatabricksRegistration,
    ) -> Result<Self, DatabricksError> {
        registration.validate_integrity()?;
        Ok(Self {
            provider,
            registration,
        })
    }

    pub fn register(
        provider: DatabricksJobsProvider<T>,
        plugin_version: &str,
        adapter_revision: &str,
        oauth_capability: OAuthCapabilitySnapshot,
        scope: DatabricksScope,
        secret_reference: SecretReference,
    ) -> Result<Self, DatabricksError> {
        let registration = DatabricksRegistration::new(
            plugin_version,
            CONTRACT_DIGEST,
            adapter_revision,
            oauth_capability,
            scope,
            secret_reference,
        )?;
        Self::new(provider, registration)
    }

    pub fn registration(&self) -> DatabricksRegistrationSnapshot {
        self.registration.snapshot()
    }

    pub fn scope(&self) -> &DatabricksScope {
        self.registration.scope()
    }

    pub fn provider(&self) -> &DatabricksJobsProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut DatabricksJobsProvider<T> {
        &mut self.provider
    }

    pub fn describe_job(&mut self) -> Result<JobDescription, DatabricksError> {
        self.ensure_active()?;
        let job = self.provider.describe_job(
            self.registration.scope(),
            self.registration.secret_reference(),
        )?;
        Ok(JobDescription {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            api_revision: JOBS_API_REVISION.to_owned(),
            job,
            registration: self.registration.snapshot(),
            provenance: self.provider.provenance(),
            native: false,
        })
    }

    pub fn compile_run_proposal(
        &self,
        job: &JobSnapshot,
        input: RunProposalInput,
    ) -> Result<RunProposal, DatabricksError> {
        self.ensure_active()?;
        RunProposal::new(
            self.registration.scope(),
            self.registration.registration_digest(),
            job,
            input,
        )
    }

    pub fn read_run_evidence(
        &mut self,
        request: &RunReadRequest,
    ) -> Result<RunEvidence, DatabricksError> {
        self.ensure_active()?;
        self.provider.read_run_evidence(
            self.registration.scope(),
            self.registration.secret_reference(),
            request,
        )
    }

    pub fn read_task_output(
        &mut self,
        run_id: u64,
        task_run_id: u64,
    ) -> Result<OutputEvidence, DatabricksError> {
        self.ensure_active()?;
        self.provider.read_task_output(
            self.registration.scope(),
            self.registration.secret_reference(),
            run_id,
            task_run_id,
        )
    }

    pub fn project_result(
        &self,
        proposal: &RunProposal,
        evidence: &RunEvidence,
        now_ms: i64,
    ) -> Result<DatabricksJobResultProposal, DatabricksError> {
        self.ensure_active()?;
        MissionDatabricksJobConsumer::new().consume(
            &self.registration.snapshot(),
            proposal,
            evidence,
            now_ms,
        )
    }

    pub fn record_run_receipt(
        &self,
        proposal: &RunProposal,
        evidence: &RunEvidence,
        recorded_at_ms: i64,
    ) -> Result<RunReceipt, DatabricksError> {
        self.ensure_active()?;
        validate_epoch(recorded_at_ms, "receipt recorded time")?;
        self.validate_pair(proposal, evidence)?;
        if evidence.is_expired_at(recorded_at_ms) {
            return Err(DatabricksError::EvidenceExpired);
        }
        let mut receipt = RunReceipt {
            receipt_version: "databricks-job-result-recording/v1".to_owned(),
            status: ReceiptStatus::MetadataRecorded,
            run_id: evidence.run.run_id,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: evidence.fingerprint.clone(),
            registration_digest: self.registration.registration_digest().to_owned(),
            scope_digest: self.registration.scope().digest(),
            provenance: evidence.provenance.clone(),
            recorded_at_ms,
            expires_at_ms: evidence.expires_at_ms,
            effect_applied: false,
            provider_receipt: false,
            native: false,
            fingerprint: String::new(),
        };
        receipt.fingerprint = receipt.recompute_fingerprint();
        Ok(receipt)
    }

    pub fn verify_job_result(
        &self,
        proposal: &RunProposal,
        evidence: &RunEvidence,
        checked_at_ms: i64,
    ) -> Result<VerificationReport, DatabricksError> {
        self.ensure_active()?;
        validate_epoch(checked_at_ms, "verification time")?;
        let mut reasons = Vec::new();
        if !proposal.verify_digest() {
            reasons.push(VerificationReason::ProposalTampered);
        }
        if !evidence.verify_fingerprint() {
            reasons.push(VerificationReason::EvidenceTampered);
        }
        if proposal.registration_digest != self.registration.registration_digest()
            || proposal.scope_digest != self.registration.scope().digest()
        {
            reasons.push(VerificationReason::RegistrationDrift);
        }
        if evidence.is_expired_at(checked_at_ms) {
            reasons.push(VerificationReason::EvidenceExpired);
        }
        if !evidence.pagination_complete {
            reasons.push(VerificationReason::PaginationIncomplete);
        }
        if !proposal.verify_digest() || !evidence.verify_fingerprint() {
            return Ok(VerificationReport::new(
                VerificationVerdict::FailedClosed,
                reasons,
                proposal.proposal_digest.clone(),
                evidence.fingerprint.clone(),
                self.registration.registration_digest().to_owned(),
                checked_at_ms,
            ));
        }
        if evidence.run.run_id == 0
            || evidence.run.job_id != proposal.job_id
            || evidence.run.job_revision != proposal.job_revision
            || !self.registration.scope().allows_run(evidence.run.run_id)
        {
            reasons.push(VerificationReason::RegistrationDrift);
        }
        let expected = proposal.ordered_task_keys.iter().collect::<BTreeSet<_>>();
        let actual = evidence
            .tasks
            .iter()
            .map(|task| &task.task_key)
            .collect::<BTreeSet<_>>();
        if !expected.is_subset(&actual) {
            reasons.push(VerificationReason::MissingTask);
        }
        if matches!(evidence.run.result_state, RunResultState::NotAvailable) {
            reasons.push(VerificationReason::TerminalWithoutResult);
        }
        if matches!(evidence.run.result_state, RunResultState::ProviderUnknown)
            || matches!(
                evidence.run.lifecycle_state,
                RunLifecycleState::ProviderUnknown
            )
        {
            reasons.push(VerificationReason::ProviderUnknown);
        }
        for task in &evidence.tasks {
            if let Some(output) = &task.output {
                if output.truncated {
                    reasons.push(VerificationReason::OutputTruncated);
                } else if output.access == OutputAccess::AccessLost {
                    reasons.push(VerificationReason::OutputMissing);
                } else if !output.is_available_at(checked_at_ms) {
                    reasons.push(VerificationReason::OutputExpired);
                }
            } else {
                reasons.push(VerificationReason::OutputMissing);
            }
        }
        reasons.sort();
        reasons.dedup();
        let verdict = if reasons.contains(&VerificationReason::MissingTask)
            || reasons.contains(&VerificationReason::EvidenceExpired)
            || reasons.contains(&VerificationReason::ProposalTampered)
            || reasons.contains(&VerificationReason::EvidenceTampered)
            || reasons.contains(&VerificationReason::RegistrationDrift)
            || reasons.contains(&VerificationReason::PaginationIncomplete)
        {
            VerificationVerdict::FailedClosed
        } else if reasons.is_empty() {
            VerificationVerdict::VerifiedMetadata
        } else {
            VerificationVerdict::PartialEvidence
        };
        Ok(VerificationReport::new(
            verdict,
            reasons,
            proposal.proposal_digest.clone(),
            evidence.fingerprint.clone(),
            self.registration.registration_digest().to_owned(),
            checked_at_ms,
        ))
    }

    pub fn revoke(&mut self) -> Result<(), DatabricksError> {
        self.registration.revoke()
    }

    pub fn reverse(&mut self) -> Result<(), DatabricksError> {
        self.registration.reverse()
    }

    fn ensure_active(&self) -> Result<(), DatabricksError> {
        self.registration.ensure_integrity_and_active()
    }

    fn validate_pair(
        &self,
        proposal: &RunProposal,
        evidence: &RunEvidence,
    ) -> Result<(), DatabricksError> {
        if !proposal.verify_digest() {
            return Err(DatabricksError::ProposalFingerprintMismatch);
        }
        if !evidence.verify_fingerprint() {
            return Err(DatabricksError::RunFingerprintMismatch);
        }
        if proposal.registration_digest != self.registration.registration_digest()
            || proposal.scope_digest != self.registration.scope().digest()
            || evidence.run.run_id == 0
            || evidence.run.job_id != proposal.job_id
            || evidence.run.job_revision != proposal.job_revision
            || !self.registration.scope().allows_run(evidence.run.run_id)
        {
            return Err(DatabricksError::RegistrationDrift);
        }
        Ok(())
    }
}

/// Deterministic metadata-only transport used by recordings and tests.
#[derive(Clone, Debug, Default)]
pub struct RecordingTransport {
    job: Option<JobSnapshot>,
    pages: BTreeMap<Option<String>, RunPage>,
    outputs: BTreeMap<u64, OutputEvidence>,
    page_calls: usize,
    output_calls: usize,
}

impl RecordingTransport {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_job(mut self, job: JobSnapshot) -> Self {
        self.job = Some(job);
        self
    }

    pub fn insert_page(&mut self, page: RunPage) {
        let inferred_page_token = page.page_token.clone().or_else(|| {
            self.pages
                .values()
                .filter_map(|existing| existing.next_page_token.clone())
                .find(|token| !self.pages.contains_key(&Some(token.clone())))
        });
        self.pages.insert(inferred_page_token, page);
    }

    #[must_use]
    pub fn with_page(mut self, page: RunPage) -> Self {
        self.insert_page(page);
        self
    }

    pub fn insert_output(&mut self, task_run_id: u64, output: OutputEvidence) {
        self.outputs.insert(task_run_id, output);
    }

    pub fn page_calls(&self) -> usize {
        self.page_calls
    }

    pub fn output_calls(&self) -> usize {
        self.output_calls
    }
}

impl DatabricksJobsTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn describe_job(
        &mut self,
        _scope: &DatabricksScope,
        _secret_reference: &SecretReference,
    ) -> Result<JobSnapshot, DatabricksProviderError> {
        self.job.clone().ok_or(DatabricksProviderError::NotFound)
    }

    fn get_run_page(
        &mut self,
        _scope: &DatabricksScope,
        _secret_reference: &SecretReference,
        _run_id: u64,
        page_token: Option<&str>,
    ) -> Result<RunPage, DatabricksProviderError> {
        self.page_calls = self.page_calls.saturating_add(1);
        self.pages
            .get(&page_token.map(str::to_owned))
            .cloned()
            .ok_or(DatabricksProviderError::NotFound)
    }

    fn get_run_output(
        &mut self,
        _scope: &DatabricksScope,
        _secret_reference: &SecretReference,
        _run_id: u64,
        task_run_id: u64,
    ) -> Result<OutputEvidence, DatabricksProviderError> {
        self.output_calls = self.output_calls.saturating_add(1);
        self.outputs
            .get(&task_run_id)
            .cloned()
            .ok_or(DatabricksProviderError::NotFound)
    }
}

/// A loopback transport is visibly distinct in provenance but remains
/// non-native and cannot report Connected.
#[derive(Clone, Debug, Default)]
pub struct LoopbackTransport {
    recording: RecordingTransport,
}

impl LoopbackTransport {
    pub fn new(recording: RecordingTransport) -> Self {
        Self { recording }
    }

    pub fn recording_mut(&mut self) -> &mut RecordingTransport {
        &mut self.recording
    }
}

impl DatabricksJobsTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn describe_job(
        &mut self,
        scope: &DatabricksScope,
        secret_reference: &SecretReference,
    ) -> Result<JobSnapshot, DatabricksProviderError> {
        self.recording.describe_job(scope, secret_reference)
    }

    fn get_run_page(
        &mut self,
        scope: &DatabricksScope,
        secret_reference: &SecretReference,
        run_id: u64,
        page_token: Option<&str>,
    ) -> Result<RunPage, DatabricksProviderError> {
        self.recording
            .get_run_page(scope, secret_reference, run_id, page_token)
    }

    fn get_run_output(
        &mut self,
        scope: &DatabricksScope,
        secret_reference: &SecretReference,
        run_id: u64,
        task_run_id: u64,
    ) -> Result<OutputEvidence, DatabricksProviderError> {
        self.recording
            .get_run_output(scope, secret_reference, run_id, task_run_id)
    }
}

/// Honest native boundary for Layer 1. Every operation fails closed and the
/// resulting provenance can never be interpreted as Connected/native.
#[derive(Clone, Debug, Default)]
pub struct BlockedEnvTransport;

impl DatabricksJobsTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn describe_job(
        &mut self,
        _scope: &DatabricksScope,
        _secret_reference: &SecretReference,
    ) -> Result<JobSnapshot, DatabricksProviderError> {
        Err(DatabricksProviderError::BlockedEnv)
    }

    fn get_run_page(
        &mut self,
        _scope: &DatabricksScope,
        _secret_reference: &SecretReference,
        _run_id: u64,
        _page_token: Option<&str>,
    ) -> Result<RunPage, DatabricksProviderError> {
        Err(DatabricksProviderError::BlockedEnv)
    }

    fn get_run_output(
        &mut self,
        _scope: &DatabricksScope,
        _secret_reference: &SecretReference,
        _run_id: u64,
        _task_run_id: u64,
    ) -> Result<OutputEvidence, DatabricksProviderError> {
        Err(DatabricksProviderError::BlockedEnv)
    }
}

impl DatabricksJobsProvider<BlockedEnvTransport> {
    pub fn blocked_env() -> Self {
        Self::new(BlockedEnvTransport)
    }
}
