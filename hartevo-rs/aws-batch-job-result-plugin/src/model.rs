//! Typed, bounded AWS Batch projections and digest fences.
//!
//! The model intentionally contains no AWS SDK payloads. It retains only
//! identifiers, bounded lifecycle information, attempt/retry/exit summaries,
//! and digests for container/artifact metadata. Commands, environments, logs,
//! images, data outputs, credentials, and raw provider JSON have no fields in
//! this module.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    AWS_BATCH_IAM_PERMISSIONS, AWS_BATCH_JOB_RESULT_CONTRACT_VERSION,
    AWS_BATCH_JOB_RESULT_PLUGIN_VERSION, AWS_BATCH_MAX_ATTEMPTS, AWS_BATCH_MAX_CHILDREN,
    AWS_BATCH_MAX_IDENTIFIER_LENGTH, AWS_BATCH_MAX_JOBS, AWS_BATCH_MAX_PAGE_SIZE,
    AWS_BATCH_MAX_PAGES,
};

pub const MAX_IDENTIFIER_LENGTH: usize = AWS_BATCH_MAX_IDENTIFIER_LENGTH;
pub const MAX_PAGE_SIZE: u16 = AWS_BATCH_MAX_PAGE_SIZE;
pub const MAX_PAGES: u16 = AWS_BATCH_MAX_PAGES;
pub const MAX_JOBS: usize = AWS_BATCH_MAX_JOBS;
pub const MAX_CHILDREN: usize = AWS_BATCH_MAX_CHILDREN;
pub const MAX_ATTEMPTS: usize = AWS_BATCH_MAX_ATTEMPTS;
pub const MAX_LIFECYCLE_EVENTS: usize = 16;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} is too long")]
    TooLong { field: &'static str },
    #[error("{field} contains a control character or surrounding whitespace")]
    InvalidText { field: &'static str },
    #[error("{field} contains unsupported whitespace")]
    InvalidWhitespace { field: &'static str },
    #[error("{field} must be positive")]
    MustBePositive { field: &'static str },
    #[error("{field} is not a SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} is not a valid bounded value")]
    InvalidValue { field: &'static str },
    #[error("{field} exceeds the configured bound")]
    BoundExceeded { field: &'static str },
    #[error("{field} is not a valid lifecycle transition")]
    InvalidTransition { field: &'static str },
    #[error("{field} is not monotonically ordered")]
    NonMonotonic { field: &'static str },
}

pub(crate) fn validate_text(value: &str, field: &'static str) -> Result<(), ModelError> {
    if value.is_empty() {
        return Err(ModelError::Empty { field });
    }
    if value.len() > MAX_IDENTIFIER_LENGTH {
        return Err(ModelError::TooLong { field });
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(ModelError::InvalidText { field });
    }
    if value.chars().any(char::is_whitespace) {
        return Err(ModelError::InvalidWhitespace { field });
    }
    Ok(())
}

macro_rules! bounded_id {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                validate_text(&value, $field)?;
                Ok(Self(value))
            }

            pub fn parse(value: impl Into<String>) -> Result<Self, ModelError> {
                Self::new(value)
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
                Self::new(value)
            }
        }
    };
}

bounded_id!(AwsAccountId, "AWS account id");
bounded_id!(AwsRegion, "AWS region");
bounded_id!(JobQueueId, "AWS Batch job queue id");
bounded_id!(JobDefinitionId, "AWS Batch job definition id");
bounded_id!(JobId, "AWS Batch job id");
bounded_id!(ProjectId, "Hartevo project id");
bounded_id!(MissionId, "Mission id");
bounded_id!(WorkProductId, "Work Product id");

pub type AccountId = AwsAccountId;
pub type Region = AwsRegion;
pub type QueueId = JobQueueId;
pub type DefinitionId = JobDefinitionId;
pub type ArrayJobId = JobId;
pub type MultiNodeJobId = JobId;
pub type MnpJobId = JobId;

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

    pub fn from_bytes(value: &[u8]) -> Self {
        Self(format!("{:x}", Sha256::digest(value)))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn from_fields<T: AsRef<str>>(namespace: &str, fields: &[T]) -> Self {
        let mut canonical = format!("{namespace}\0");
        for field in fields {
            let value = field.as_ref();
            canonical.push_str(&value.len().to_string());
            canonical.push(':');
            canonical.push_str(value);
            canonical.push('\0');
        }
        Self::from_text(canonical)
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

pub fn sha256_digest(value: &[u8]) -> Digest {
    Digest::from_bytes(value)
}

pub fn digest_serializable<T: Serialize + ?Sized>(value: &T) -> Result<Digest, ModelError> {
    serde_json::to_vec(value)
        .map(|bytes| sha256_digest(&bytes))
        .map_err(|_| ModelError::InvalidValue {
            field: "canonical digest input",
        })
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        if value == 0 {
            Err(ModelError::MustBePositive { field: "revision" })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AttemptNumber(u32);

impl AttemptNumber {
    pub fn new(value: u32) -> Result<Self, ModelError> {
        if value == 0 {
            return Err(ModelError::MustBePositive { field: "attempt" });
        }
        if value as usize > MAX_ATTEMPTS {
            return Err(ModelError::BoundExceeded { field: "attempt" });
        }
        Ok(Self(value))
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

pub type Attempt = AttemptNumber;
pub type Timestamp = u64;

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
}

/// The complete Project/Mission/Work Product and AWS Batch execution fence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AwsBatchScope {
    pub account_id: AwsAccountId,
    pub region: AwsRegion,
    pub job_queue_id: JobQueueId,
    pub job_definition_id: JobDefinitionId,
    pub job_id: JobId,
    pub array_job_id: Option<JobId>,
    pub multi_node_job_id: Option<JobId>,
    pub attempt: Option<AttemptNumber>,
    pub project_id: ProjectId,
    pub project_revision: Revision,
    pub mission_id: MissionId,
    pub mission_revision: Revision,
    pub work_product_id: WorkProductId,
    pub work_product_revision: Revision,
    pub permission_digest: Digest,
}

impl AwsBatchScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: AwsAccountId,
        region: AwsRegion,
        job_queue_id: JobQueueId,
        job_definition_id: JobDefinitionId,
        job_id: JobId,
        project_id: ProjectId,
        mission_id: MissionId,
        work_product_id: WorkProductId,
    ) -> Self {
        Self {
            account_id,
            region,
            job_queue_id,
            job_definition_id,
            job_id,
            array_job_id: None,
            multi_node_job_id: None,
            attempt: None,
            project_id,
            project_revision: Revision(1),
            mission_id,
            mission_revision: Revision(1),
            work_product_id,
            work_product_revision: Revision(1),
            permission_digest: crate::permission_digest(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_execution_fences(
        account_id: AwsAccountId,
        region: AwsRegion,
        job_queue_id: JobQueueId,
        job_definition_id: JobDefinitionId,
        job_id: JobId,
        array_job_id: Option<JobId>,
        multi_node_job_id: Option<JobId>,
        attempt: Option<AttemptNumber>,
        project_id: ProjectId,
        project_revision: Revision,
        mission_id: MissionId,
        mission_revision: Revision,
        work_product_id: WorkProductId,
        work_product_revision: Revision,
        permission_digest: Digest,
    ) -> Result<Self, ModelError> {
        let scope = Self {
            account_id,
            region,
            job_queue_id,
            job_definition_id,
            job_id,
            array_job_id,
            multi_node_job_id,
            attempt,
            project_id,
            project_revision,
            mission_id,
            mission_revision,
            work_product_id,
            work_product_revision,
            permission_digest,
        };
        scope.validate()?;
        Ok(scope)
    }

    #[must_use]
    pub fn with_array_job_id(mut self, value: JobId) -> Self {
        self.array_job_id = Some(value);
        self
    }

    #[must_use]
    pub fn with_array_job(mut self, value: JobId) -> Self {
        self.array_job_id = Some(value);
        self
    }

    #[must_use]
    pub fn with_multi_node_job_id(mut self, value: JobId) -> Self {
        self.multi_node_job_id = Some(value);
        self
    }

    #[must_use]
    pub fn with_mnp_job_id(mut self, value: JobId) -> Self {
        self.multi_node_job_id = Some(value);
        self
    }

    #[must_use]
    pub fn with_attempt(mut self, value: AttemptNumber) -> Self {
        self.attempt = Some(value);
        self
    }

    pub fn with_attempt_number(mut self, value: u32) -> Result<Self, ModelError> {
        self.attempt = Some(AttemptNumber::new(value)?);
        Ok(self)
    }

    #[must_use]
    pub fn with_revisions(
        mut self,
        project_revision: Revision,
        mission_revision: Revision,
        work_product_revision: Revision,
    ) -> Self {
        self.project_revision = project_revision;
        self.mission_revision = mission_revision;
        self.work_product_revision = work_product_revision;
        self
    }

    #[must_use]
    pub fn with_permission_digest(mut self, value: Digest) -> Self {
        self.permission_digest = value;
        self
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.array_job_id.is_some() && self.multi_node_job_id.is_some() {
            return Err(ModelError::InvalidValue {
                field: "array and multi-node job fence",
            });
        }
        validate_text(self.account_id.as_str(), "AWS account id")?;
        validate_text(self.region.as_str(), "AWS region")?;
        validate_text(self.job_queue_id.as_str(), "AWS Batch job queue id")?;
        validate_text(
            self.job_definition_id.as_str(),
            "AWS Batch job definition id",
        )?;
        validate_text(self.job_id.as_str(), "AWS Batch job id")?;
        if let Some(array_job_id) = &self.array_job_id {
            validate_text(array_job_id.as_str(), "AWS Batch array job id")?;
        }
        if let Some(multi_node_job_id) = &self.multi_node_job_id {
            validate_text(multi_node_job_id.as_str(), "AWS Batch multi-node job id")?;
        }
        validate_text(self.project_id.as_str(), "Hartevo project id")?;
        validate_text(self.mission_id.as_str(), "Mission id")?;
        validate_text(self.work_product_id.as_str(), "Work Product id")?;
        Revision::new(self.project_revision.get())?;
        Revision::new(self.mission_revision.get())?;
        Revision::new(self.work_product_revision.get())?;
        Digest::parse(self.permission_digest.as_str())?;
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        digest_serializable(self).expect("AwsBatchScope is serializable")
    }

    pub fn scope_digest(&self) -> Digest {
        self.digest()
    }

    pub fn job_digest(&self) -> Digest {
        Digest::from_fields(
            "hartevo.aws-batch-job-fence/v1",
            &[
                self.account_id.as_str().to_owned(),
                self.region.as_str().to_owned(),
                self.job_queue_id.as_str().to_owned(),
                self.job_definition_id.as_str().to_owned(),
                self.job_id.as_str().to_owned(),
                self.array_job_id
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
                self.multi_node_job_id
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
            ],
        )
    }

    pub fn attempt_digest(&self) -> Digest {
        Digest::from_fields(
            "hartevo.aws-batch-attempt-fence/v1",
            &[
                self.job_digest().as_str().to_owned(),
                self.attempt
                    .map_or_else(String::new, |value| value.get().to_string()),
            ],
        )
    }

    pub fn account(&self) -> &AwsAccountId {
        &self.account_id
    }

    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    pub fn job_queue(&self) -> &JobQueueId {
        &self.job_queue_id
    }

    pub fn job_definition(&self) -> &JobDefinitionId {
        &self.job_definition_id
    }

    pub fn job(&self) -> &JobId {
        &self.job_id
    }

    pub fn project(&self) -> &ProjectId {
        &self.project_id
    }

    pub fn mission(&self) -> &MissionId {
        &self.mission_id
    }

    pub fn work_product(&self) -> &WorkProductId {
        &self.work_product_id
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }
}

/// Host-owned credential identity. The raw reference is private and this
/// type intentionally does not implement `Serialize` or `Deserialize`.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct SigV4SecretReference {
    reference_id: String,
    scope_digest: Digest,
    credential_revision: Revision,
}

impl SigV4SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope: &AwsBatchScope,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        validate_text(&reference_id, "SigV4 secret reference")?;
        Ok(Self {
            reference_id,
            scope_digest: scope.digest(),
            credential_revision: Revision::new(credential_revision)?,
        })
    }

    pub fn from_scope_digest(
        reference_id: impl Into<String>,
        scope_digest: Digest,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        validate_text(&reference_id, "SigV4 secret reference")?;
        let scope_digest = Digest::parse(scope_digest.0)?;
        Ok(Self {
            reference_id,
            scope_digest,
            credential_revision: Revision::new(credential_revision)?,
        })
    }

    pub fn reference_digest(&self) -> Digest {
        Digest::from_fields(
            "hartevo.sigv4-secret-reference/v1",
            &[
                self.reference_id.clone(),
                self.scope_digest.as_str().to_owned(),
                self.credential_revision.get().to_string(),
            ],
        )
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    pub fn is_for_scope(&self, scope: &AwsBatchScope) -> bool {
        self.scope_digest == scope.digest()
    }
}

impl fmt::Debug for SigV4SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SigV4SecretReference")
            .field("reference_digest", &self.reference_digest())
            .field("scope_digest", &self.scope_digest)
            .field("credential_revision", &self.credential_revision)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for SigV4SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "SigV4SecretReference({})",
            self.reference_digest()
        )
    }
}

pub type SecretReference = SigV4SecretReference;
pub type AwsSigV4SecretReference = SigV4SecretReference;
pub type AwsBatchJobResultScope = AwsBatchScope;
pub type AwsBatchExecutionScope = AwsBatchScope;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Submitted,
    Pending,
    Runnable,
    Starting,
    Running,
    Succeeded,
    Failed,
    Unknown,
}

pub type AwsBatchJobStatus = JobStatus;
pub type JobLifecycleStatus = JobStatus;

impl JobStatus {
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed)
    }

    pub const fn is_unknown(self) -> bool {
        matches!(self, Self::Unknown)
    }

    pub fn allows_transition_to(self, next: Self) -> bool {
        if self == next {
            return true;
        }
        match self {
            Self::Submitted => matches!(
                next,
                Self::Pending | Self::Runnable | Self::Starting | Self::Running | Self::Failed
            ),
            Self::Pending => matches!(
                next,
                Self::Runnable | Self::Starting | Self::Running | Self::Failed
            ),
            Self::Runnable => matches!(next, Self::Starting | Self::Running | Self::Failed),
            Self::Starting => matches!(next, Self::Running | Self::Failed),
            Self::Running => matches!(next, Self::Succeeded | Self::Failed),
            Self::Succeeded | Self::Failed => false,
            Self::Unknown => matches!(next, Self::Unknown),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LifecycleEvent {
    pub status: JobStatus,
    pub observed_at: Timestamp,
    pub event_digest: Digest,
}

impl LifecycleEvent {
    pub fn new(status: JobStatus, observed_at: Timestamp) -> Self {
        let event_digest = Digest::from_fields(
            "hartevo.aws-batch-lifecycle-event/v1",
            &[format!("{status:?}"), observed_at.to_string()],
        );
        Self {
            status,
            observed_at,
            event_digest,
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let expected = Self::new(self.status, self.observed_at).event_digest;
        if self.event_digest != expected {
            return Err(ModelError::InvalidDigest {
                field: "lifecycle event",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LifecycleSummary {
    pub current_status: JobStatus,
    pub first_observed_at: Option<Timestamp>,
    pub started_at: Option<Timestamp>,
    pub stopped_at: Option<Timestamp>,
    pub events: Vec<LifecycleEvent>,
    pub lifecycle_digest: Digest,
}

impl LifecycleSummary {
    pub fn from_events(events: Vec<LifecycleEvent>) -> Result<Self, ModelError> {
        if events.is_empty() || events.len() > MAX_LIFECYCLE_EVENTS {
            return Err(ModelError::BoundExceeded {
                field: "lifecycle events",
            });
        }
        for event in &events {
            event.validate()?;
        }
        for pair in events.windows(2) {
            if pair[1].observed_at < pair[0].observed_at {
                return Err(ModelError::NonMonotonic {
                    field: "lifecycle timestamps",
                });
            }
            if !pair[0].status.allows_transition_to(pair[1].status) {
                return Err(ModelError::InvalidTransition {
                    field: "job lifecycle",
                });
            }
        }
        let current_status = events.last().expect("non-empty events").status;
        let first_observed_at = events.first().map(|event| event.observed_at);
        let started_at = events
            .iter()
            .find(|event| matches!(event.status, JobStatus::Running))
            .map(|event| event.observed_at);
        let stopped_at = events
            .iter()
            .find(|event| event.status.is_terminal())
            .map(|event| event.observed_at);
        let lifecycle_digest = digest_serializable(&events)?;
        Ok(Self {
            current_status,
            first_observed_at,
            started_at,
            stopped_at,
            events,
            lifecycle_digest,
        })
    }

    pub fn single(status: JobStatus, observed_at: Timestamp) -> Result<Self, ModelError> {
        Self::from_events(vec![LifecycleEvent::new(status, observed_at)])
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let expected = Self::from_events(self.events.clone())?;
        if self.current_status != expected.current_status
            || self.first_observed_at != expected.first_observed_at
            || self.started_at != expected.started_at
            || self.stopped_at != expected.stopped_at
            || self.lifecycle_digest != expected.lifecycle_digest
        {
            return Err(ModelError::InvalidDigest {
                field: "lifecycle summary",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactedBatchField {
    CommandArguments,
    Environment,
    Logs,
    ContainerImage,
    DataOutputs,
    RawProviderPayload,
    Credentials,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionSummary {
    pub redacted_fields: Vec<RedactedBatchField>,
    pub raw_provider_payload_retained: bool,
}

impl Default for RedactionSummary {
    fn default() -> Self {
        Self {
            redacted_fields: vec![
                RedactedBatchField::CommandArguments,
                RedactedBatchField::Environment,
                RedactedBatchField::Logs,
                RedactedBatchField::ContainerImage,
                RedactedBatchField::DataOutputs,
                RedactedBatchField::RawProviderPayload,
                RedactedBatchField::Credentials,
            ],
            raw_provider_payload_retained: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContainerArtifactMetadata {
    pub container_metadata_digest: Digest,
    pub artifact_metadata_digest: Option<Digest>,
    pub redaction: RedactionSummary,
}

impl ContainerArtifactMetadata {
    pub fn new(container_metadata_digest: Digest) -> Self {
        Self {
            container_metadata_digest,
            artifact_metadata_digest: None,
            redaction: RedactionSummary::default(),
        }
    }

    #[must_use]
    pub fn with_artifact_metadata_digest(mut self, value: Digest) -> Self {
        self.artifact_metadata_digest = Some(value);
        self
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.redaction.raw_provider_payload_retained {
            return Err(ModelError::InvalidValue {
                field: "raw provider payload retention",
            });
        }
        Ok(())
    }
}

pub type ContainerArtifactDigest = ContainerArtifactMetadata;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AttemptSummary {
    pub attempt: AttemptNumber,
    pub status: JobStatus,
    pub started_at: Option<Timestamp>,
    pub stopped_at: Option<Timestamp>,
    pub exit_code: Option<i32>,
    pub reason_digest: Option<Digest>,
    pub container_metadata_digest: Digest,
    pub artifact_metadata_digest: Option<Digest>,
    pub redaction: RedactionSummary,
    pub attempt_digest: Digest,
}

impl AttemptSummary {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        attempt: AttemptNumber,
        status: JobStatus,
        started_at: Option<Timestamp>,
        stopped_at: Option<Timestamp>,
        exit_code: Option<i32>,
        container_metadata_digest: Digest,
        artifact_metadata_digest: Option<Digest>,
    ) -> Result<Self, ModelError> {
        if let (Some(started), Some(stopped)) = (started_at, stopped_at)
            && stopped < started
        {
            return Err(ModelError::NonMonotonic {
                field: "attempt timestamps",
            });
        }
        let mut summary = Self {
            attempt,
            status,
            started_at,
            stopped_at,
            exit_code,
            reason_digest: None,
            container_metadata_digest,
            artifact_metadata_digest,
            redaction: RedactionSummary::default(),
            attempt_digest: Digest::from_text("pending-attempt-digest"),
        };
        summary.attempt_digest = summary.compute_digest()?;
        Ok(summary)
    }

    pub fn with_reason_digest(mut self, value: Digest) -> Result<Self, ModelError> {
        self.reason_digest = Some(value);
        self.attempt_digest = self.compute_digest()?;
        Ok(self)
    }

    fn compute_digest(&self) -> Result<Digest, ModelError> {
        digest_serializable(&(
            self.attempt,
            self.status,
            self.started_at,
            self.stopped_at,
            self.exit_code,
            &self.reason_digest,
            &self.container_metadata_digest,
            &self.artifact_metadata_digest,
            &self.redaction,
        ))
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.redaction.raw_provider_payload_retained
            || self.attempt_digest != self.compute_digest()?
        {
            return Err(ModelError::InvalidDigest {
                field: "attempt summary",
            });
        }
        if let (Some(started), Some(stopped)) = (self.started_at, self.stopped_at)
            && stopped < started
        {
            return Err(ModelError::NonMonotonic {
                field: "attempt timestamps",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetrySummary {
    pub total_attempts: u16,
    pub retry_count: u16,
    pub succeeded_attempts: u16,
    pub failed_attempts: u16,
    pub last_attempt: AttemptNumber,
    pub attempts_digest: Digest,
}

impl RetrySummary {
    pub fn from_attempts(attempts: &[AttemptSummary]) -> Result<Self, ModelError> {
        if attempts.is_empty() || attempts.len() > MAX_ATTEMPTS {
            return Err(ModelError::BoundExceeded {
                field: "attempt summaries",
            });
        }
        for attempt in attempts {
            attempt.validate()?;
        }
        for pair in attempts.windows(2) {
            if pair[1].attempt.get() != pair[0].attempt.get() + 1 {
                return Err(ModelError::NonMonotonic {
                    field: "attempt numbers",
                });
            }
        }
        let total_attempts =
            u16::try_from(attempts.len()).map_err(|_| ModelError::BoundExceeded {
                field: "attempt summaries",
            })?;
        let succeeded_attempts = u16::try_from(
            attempts
                .iter()
                .filter(|attempt| attempt.status == JobStatus::Succeeded)
                .count(),
        )
        .map_err(|_| ModelError::BoundExceeded {
            field: "succeeded attempts",
        })?;
        let failed_attempts = u16::try_from(
            attempts
                .iter()
                .filter(|attempt| attempt.status == JobStatus::Failed)
                .count(),
        )
        .map_err(|_| ModelError::BoundExceeded {
            field: "failed attempts",
        })?;
        Ok(Self {
            total_attempts,
            retry_count: total_attempts.saturating_sub(1),
            succeeded_attempts,
            failed_attempts,
            last_attempt: attempts.last().expect("non-empty attempts").attempt,
            attempts_digest: digest_serializable(attempts)?,
        })
    }

    pub fn validate_against(&self, attempts: &[AttemptSummary]) -> Result<(), ModelError> {
        let expected = Self::from_attempts(attempts)?;
        if self != &expected {
            return Err(ModelError::InvalidDigest {
                field: "retry summary",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExitCodeSummary {
    pub observed_codes: Vec<i32>,
    pub successful_count: u16,
    pub failed_count: u16,
    pub exit_codes_digest: Digest,
}

impl ExitCodeSummary {
    pub fn from_attempts(attempts: &[AttemptSummary]) -> Result<Self, ModelError> {
        if attempts.len() > MAX_ATTEMPTS {
            return Err(ModelError::BoundExceeded {
                field: "exit code summaries",
            });
        }
        let observed_codes: Vec<i32> = attempts
            .iter()
            .filter_map(|attempt| attempt.exit_code)
            .collect();
        let successful_count = u16::try_from(
            observed_codes.iter().filter(|code| **code == 0).count(),
        )
        .map_err(|_| ModelError::BoundExceeded {
            field: "successful exit codes",
        })?;
        let failed_count = u16::try_from(observed_codes.iter().filter(|code| **code != 0).count())
            .map_err(|_| ModelError::BoundExceeded {
                field: "failed exit codes",
            })?;
        Ok(Self {
            exit_codes_digest: digest_serializable(&observed_codes)?,
            observed_codes,
            successful_count,
            failed_count,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let successful_count = u16::try_from(
            self.observed_codes
                .iter()
                .filter(|code| **code == 0)
                .count(),
        )
        .map_err(|_| ModelError::BoundExceeded {
            field: "successful exit codes",
        })?;
        let failed_count = u16::try_from(
            self.observed_codes
                .iter()
                .filter(|code| **code != 0)
                .count(),
        )
        .map_err(|_| ModelError::BoundExceeded {
            field: "failed exit codes",
        })?;
        if self.observed_codes.len() > MAX_ATTEMPTS
            || self.exit_codes_digest != digest_serializable(&self.observed_codes)?
            || self.successful_count != successful_count
            || self.failed_count != failed_count
        {
            return Err(ModelError::InvalidDigest {
                field: "exit code summary",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChildProjectionKind {
    ArrayChild,
    MultiNodeNode,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JobChildProjection {
    pub child_job_id: JobId,
    pub parent_job_id: JobId,
    pub kind: ChildProjectionKind,
    pub index: u32,
    pub is_main_node: Option<bool>,
    pub job_queue_id: JobQueueId,
    pub job_definition_id: JobDefinitionId,
    pub status: JobStatus,
    pub started_at: Option<Timestamp>,
    pub stopped_at: Option<Timestamp>,
    pub attempts: Vec<AttemptSummary>,
    pub retry: RetrySummary,
    pub exit_codes: ExitCodeSummary,
    pub metadata: ContainerArtifactMetadata,
    pub projection_digest: Digest,
}

pub type ArrayChildProjection = JobChildProjection;
pub type MnpNodeProjection = JobChildProjection;

impl JobChildProjection {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        child_job_id: JobId,
        parent_job_id: JobId,
        kind: ChildProjectionKind,
        index: u32,
        is_main_node: Option<bool>,
        job_queue_id: JobQueueId,
        job_definition_id: JobDefinitionId,
        status: JobStatus,
        started_at: Option<Timestamp>,
        stopped_at: Option<Timestamp>,
        attempts: Vec<AttemptSummary>,
        metadata: ContainerArtifactMetadata,
    ) -> Result<Self, ModelError> {
        if matches!(kind, ChildProjectionKind::ArrayChild) && is_main_node.is_some() {
            return Err(ModelError::InvalidValue {
                field: "array child main-node marker",
            });
        }
        if attempts.len() > MAX_ATTEMPTS || attempts.is_empty() {
            return Err(ModelError::BoundExceeded {
                field: "child attempts",
            });
        }
        let retry = RetrySummary::from_attempts(&attempts)?;
        let exit_codes = ExitCodeSummary::from_attempts(&attempts)?;
        if attempts.last().expect("non-empty attempts").status != status {
            return Err(ModelError::InvalidValue {
                field: "child current status",
            });
        }
        let mut projection = Self {
            child_job_id,
            parent_job_id,
            kind,
            index,
            is_main_node,
            job_queue_id,
            job_definition_id,
            status,
            started_at,
            stopped_at,
            attempts,
            retry,
            exit_codes,
            metadata,
            projection_digest: Digest::from_text("pending-child-digest"),
        };
        projection.projection_digest = projection.compute_digest()?;
        Ok(projection)
    }

    fn compute_digest(&self) -> Result<Digest, ModelError> {
        digest_serializable(&(
            &self.child_job_id,
            &self.parent_job_id,
            self.kind,
            self.index,
            self.is_main_node,
            &self.job_queue_id,
            &self.job_definition_id,
            self.status,
            self.started_at,
            self.stopped_at,
            &self.attempts,
            &self.retry,
            &self.exit_codes,
            &self.metadata,
        ))
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.attempts.is_empty()
            || self.attempts.len() > MAX_ATTEMPTS
            || self
                .attempts
                .iter()
                .any(|attempt| attempt.validate().is_err())
            || self.attempts.last().map(|attempt| attempt.status) != Some(self.status)
            || self.retry.validate_against(&self.attempts).is_err()
            || self.exit_codes.validate().is_err()
            || self.metadata.validate().is_err()
            || self.projection_digest != self.compute_digest()?
        {
            return Err(ModelError::InvalidDigest {
                field: "child projection",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArrayProjection {
    pub parent_job_id: JobId,
    pub size: u32,
    pub children: Vec<ArrayChildProjection>,
    pub status_summary: Vec<StatusCount>,
    pub projection_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MnpProjection {
    pub parent_job_id: JobId,
    pub num_nodes: u32,
    pub main_node: u32,
    pub nodes: Vec<MnpNodeProjection>,
    pub status_summary: Vec<StatusCount>,
    pub projection_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatusCount {
    pub status: JobStatus,
    pub count: u16,
}

fn status_counts(children: &[JobChildProjection]) -> Vec<StatusCount> {
    let mut counts = Vec::<StatusCount>::new();
    for child in children {
        if let Some(existing) = counts.iter_mut().find(|item| item.status == child.status) {
            existing.count = existing.count.saturating_add(1);
        } else {
            counts.push(StatusCount {
                status: child.status,
                count: 1,
            });
        }
    }
    counts.sort_by_key(|item| item.status);
    counts
}

impl ArrayProjection {
    pub fn new(
        parent_job_id: JobId,
        size: u32,
        children: Vec<ArrayChildProjection>,
    ) -> Result<Self, ModelError> {
        if children.is_empty()
            || children.len() > MAX_CHILDREN
            || size == 0
            || u32::try_from(children.len()).is_ok_and(|count| count > size)
        {
            return Err(ModelError::BoundExceeded {
                field: "array children",
            });
        }
        for child in &children {
            child.validate()?;
            if child.kind != ChildProjectionKind::ArrayChild
                || child.parent_job_id != parent_job_id
                || child.index >= size
            {
                return Err(ModelError::InvalidValue {
                    field: "array child fence",
                });
            }
        }
        let status_summary = status_counts(&children);
        let projection_digest =
            digest_serializable(&(&parent_job_id, size, &children, &status_summary))?;
        Ok(Self {
            parent_job_id,
            size,
            children,
            status_summary,
            projection_digest,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let expected = Self::new(self.parent_job_id.clone(), self.size, self.children.clone())?;
        if self != &expected {
            return Err(ModelError::InvalidDigest {
                field: "array projection",
            });
        }
        Ok(())
    }
}

impl MnpProjection {
    pub fn new(
        parent_job_id: JobId,
        num_nodes: u32,
        main_node: u32,
        nodes: Vec<MnpNodeProjection>,
    ) -> Result<Self, ModelError> {
        if nodes.is_empty()
            || nodes.len() > MAX_CHILDREN
            || num_nodes == 0
            || main_node >= num_nodes
            || u32::try_from(nodes.len()).is_ok_and(|count| count > num_nodes)
        {
            return Err(ModelError::BoundExceeded {
                field: "multi-node children",
            });
        }
        for node in &nodes {
            node.validate()?;
            if node.kind != ChildProjectionKind::MultiNodeNode
                || node.parent_job_id != parent_job_id
                || node.index >= num_nodes
                || (node.is_main_node == Some(true) && node.index != main_node)
                || (node.index == main_node && node.is_main_node == Some(false))
            {
                return Err(ModelError::InvalidValue {
                    field: "multi-node child fence",
                });
            }
        }
        let status_summary = status_counts(&nodes);
        let projection_digest = digest_serializable(&(
            &parent_job_id,
            num_nodes,
            main_node,
            &nodes,
            &status_summary,
        ))?;
        Ok(Self {
            parent_job_id,
            num_nodes,
            main_node,
            nodes,
            status_summary,
            projection_digest,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let expected = Self::new(
            self.parent_job_id.clone(),
            self.num_nodes,
            self.main_node,
            self.nodes.clone(),
        )?;
        if self != &expected {
            return Err(ModelError::InvalidDigest {
                field: "multi-node projection",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JobProjection {
    pub job_id: JobId,
    pub parent_job_id: Option<JobId>,
    pub job_queue_id: JobQueueId,
    pub job_definition_id: JobDefinitionId,
    pub status: JobStatus,
    pub created_at: Option<Timestamp>,
    pub started_at: Option<Timestamp>,
    pub stopped_at: Option<Timestamp>,
    pub lifecycle: LifecycleSummary,
    pub attempts: Vec<AttemptSummary>,
    pub retry: RetrySummary,
    pub exit_codes: ExitCodeSummary,
    pub metadata: ContainerArtifactMetadata,
    pub array: Option<ArrayProjection>,
    pub multi_node: Option<MnpProjection>,
    pub projection_digest: Digest,
}

pub type AwsBatchJobProjection = JobProjection;

impl JobProjection {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        job_id: JobId,
        parent_job_id: Option<JobId>,
        job_queue_id: JobQueueId,
        job_definition_id: JobDefinitionId,
        status: JobStatus,
        created_at: Option<Timestamp>,
        started_at: Option<Timestamp>,
        stopped_at: Option<Timestamp>,
        lifecycle: LifecycleSummary,
        attempts: Vec<AttemptSummary>,
        metadata: ContainerArtifactMetadata,
        array: Option<ArrayProjection>,
        multi_node: Option<MnpProjection>,
    ) -> Result<Self, ModelError> {
        if array.is_some() && multi_node.is_some() {
            return Err(ModelError::InvalidValue {
                field: "array and multi-node projections",
            });
        }
        if attempts.is_empty() || attempts.len() > MAX_ATTEMPTS {
            return Err(ModelError::BoundExceeded {
                field: "job attempts",
            });
        }
        lifecycle.validate()?;
        let retry = RetrySummary::from_attempts(&attempts)?;
        let exit_codes = ExitCodeSummary::from_attempts(&attempts)?;
        if attempts.last().expect("non-empty attempts").status != status {
            return Err(ModelError::InvalidValue {
                field: "job current status",
            });
        }
        if lifecycle.current_status != status {
            return Err(ModelError::InvalidValue {
                field: "job lifecycle status",
            });
        }
        if let (Some(started), Some(stopped)) = (started_at, stopped_at)
            && stopped < started
        {
            return Err(ModelError::NonMonotonic {
                field: "job timestamps",
            });
        }
        if let Some(array_projection) = &array {
            array_projection.validate()?;
            if array_projection.parent_job_id != job_id {
                return Err(ModelError::InvalidValue {
                    field: "array parent job",
                });
            }
        }
        if let Some(mnp_projection) = &multi_node {
            mnp_projection.validate()?;
            if mnp_projection.parent_job_id != job_id {
                return Err(ModelError::InvalidValue {
                    field: "multi-node parent job",
                });
            }
        }
        let mut projection = Self {
            job_id,
            parent_job_id,
            job_queue_id,
            job_definition_id,
            status,
            created_at,
            started_at,
            stopped_at,
            lifecycle,
            attempts,
            retry,
            exit_codes,
            metadata,
            array,
            multi_node,
            projection_digest: Digest::from_text("pending-job-digest"),
        };
        projection.projection_digest = projection.compute_digest()?;
        Ok(projection)
    }

    fn compute_digest(&self) -> Result<Digest, ModelError> {
        digest_serializable(&(
            &self.job_id,
            &self.parent_job_id,
            &self.job_queue_id,
            &self.job_definition_id,
            self.status,
            self.created_at,
            self.started_at,
            self.stopped_at,
            &self.lifecycle,
            &self.attempts,
            &self.retry,
            &self.exit_codes,
            &self.metadata,
            &self.array,
            &self.multi_node,
        ))
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.attempts.is_empty()
            || self.attempts.len() > MAX_ATTEMPTS
            || self.lifecycle.validate().is_err()
            || self.lifecycle.current_status != self.status
            || self
                .attempts
                .iter()
                .any(|attempt| attempt.validate().is_err())
            || self.attempts.last().map(|attempt| attempt.status) != Some(self.status)
            || self.retry.validate_against(&self.attempts).is_err()
            || self.exit_codes.validate().is_err()
            || self.metadata.validate().is_err()
            || self
                .array
                .as_ref()
                .is_some_and(|value| value.validate().is_err())
            || self
                .multi_node
                .as_ref()
                .is_some_and(|value| value.validate().is_err())
            || self.projection_digest != self.compute_digest()?
        {
            return Err(ModelError::InvalidDigest {
                field: "job projection",
            });
        }
        Ok(())
    }

    pub fn validate_against(&self, scope: &AwsBatchScope) -> Result<(), ModelError> {
        scope.validate()?;
        self.validate()?;
        if self.job_queue_id != scope.job_queue_id
            || self.job_definition_id != scope.job_definition_id
        {
            return Err(ModelError::InvalidValue {
                field: "job queue or definition fence",
            });
        }
        let is_root = self.job_id == scope.job_id;
        let is_array_child = scope
            .array_job_id
            .as_ref()
            .is_some_and(|parent| self.parent_job_id.as_ref() == Some(parent));
        let is_mnp_child = scope
            .multi_node_job_id
            .as_ref()
            .is_some_and(|parent| self.parent_job_id.as_ref() == Some(parent));
        if !is_root && !is_array_child && !is_mnp_child {
            return Err(ModelError::InvalidValue {
                field: "job id fence",
            });
        }
        if is_root {
            let expected_parent = scope
                .array_job_id
                .as_ref()
                .filter(|parent| *parent != &scope.job_id)
                .or_else(|| {
                    scope
                        .multi_node_job_id
                        .as_ref()
                        .filter(|parent| *parent != &scope.job_id)
                });
            if self.parent_job_id.as_ref() != expected_parent {
                return Err(ModelError::InvalidValue {
                    field: "root parent job fence",
                });
            }
        }
        if let Some(attempt) = scope.attempt
            && (self.attempts.len() != 1 || self.attempts[0].attempt != attempt)
        {
            return Err(ModelError::InvalidValue {
                field: "attempt fence",
            });
        }
        if let Some(array_projection) = &self.array {
            if scope.array_job_id.as_ref() != Some(&self.job_id) {
                return Err(ModelError::InvalidValue {
                    field: "array job fence",
                });
            }
            array_projection.validate()?;
        }
        if let Some(mnp_projection) = &self.multi_node {
            if scope.multi_node_job_id.as_ref() != Some(&self.job_id) {
                return Err(ModelError::InvalidValue {
                    field: "multi-node job fence",
                });
            }
            mnp_projection.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JobSummary {
    pub job_id: JobId,
    pub parent_job_id: Option<JobId>,
    pub job_queue_id: JobQueueId,
    pub job_definition_id: JobDefinitionId,
    pub status: JobStatus,
    pub started_at: Option<Timestamp>,
    pub stopped_at: Option<Timestamp>,
    pub array_index: Option<u32>,
    pub node_index: Option<u32>,
    pub is_main_node: Option<bool>,
    pub summary_digest: Digest,
}

impl JobSummary {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        job_id: JobId,
        parent_job_id: Option<JobId>,
        job_queue_id: JobQueueId,
        job_definition_id: JobDefinitionId,
        status: JobStatus,
        started_at: Option<Timestamp>,
        stopped_at: Option<Timestamp>,
        array_index: Option<u32>,
        node_index: Option<u32>,
        is_main_node: Option<bool>,
    ) -> Result<Self, ModelError> {
        if array_index.is_some() && node_index.is_some() {
            return Err(ModelError::InvalidValue {
                field: "array and multi-node summary indexes",
            });
        }
        let mut summary = Self {
            job_id,
            parent_job_id,
            job_queue_id,
            job_definition_id,
            status,
            started_at,
            stopped_at,
            array_index,
            node_index,
            is_main_node,
            summary_digest: Digest::from_text("pending-summary-digest"),
        };
        summary.summary_digest = digest_serializable(&(
            &summary.job_id,
            &summary.parent_job_id,
            &summary.job_queue_id,
            &summary.job_definition_id,
            summary.status,
            summary.started_at,
            summary.stopped_at,
            summary.array_index,
            summary.node_index,
            summary.is_main_node,
        ))?;
        Ok(summary)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let expected = Self::new(
            self.job_id.clone(),
            self.parent_job_id.clone(),
            self.job_queue_id.clone(),
            self.job_definition_id.clone(),
            self.status,
            self.started_at,
            self.stopped_at,
            self.array_index,
            self.node_index,
            self.is_main_node,
        )?;
        if self != &expected {
            return Err(ModelError::InvalidDigest {
                field: "job summary",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Complete,
    Partial,
    AccessLost,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessLossKind {
    BlockedEnv,
    BadRequest,
    Unauthorized,
    AccessDenied,
    NotFound,
    Conflict,
    Throttled,
    ProviderUnavailable,
    Timeout,
    MalformedResponse,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccessLossEvidence {
    pub kind: AccessLossKind,
    pub provider_code: String,
    pub operation: String,
    pub after_page: u16,
    pub detail_digest: Digest,
}

impl AccessLossEvidence {
    pub fn new(
        kind: AccessLossKind,
        provider_code: impl Into<String>,
        operation: impl Into<String>,
        after_page: u16,
    ) -> Result<Self, ModelError> {
        let provider_code = provider_code.into();
        let operation = operation.into();
        validate_text(&provider_code, "provider access-loss code")?;
        validate_text(&operation, "provider operation")?;
        Ok(Self {
            detail_digest: Digest::from_fields(
                "hartevo.aws-batch-access-loss/v1",
                &[
                    provider_code.clone(),
                    operation.clone(),
                    after_page.to_string(),
                ],
            ),
            kind,
            provider_code,
            operation,
            after_page,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        let expected = Self::new(
            self.kind,
            self.provider_code.clone(),
            self.operation.clone(),
            self.after_page,
        )?;
        if self != &expected {
            return Err(ModelError::InvalidDigest {
                field: "access-loss evidence",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialReason {
    ProviderMarkedPartial,
    PageLimitReached,
    JobLimitReached,
    ChildLimitReached,
    DescribeBatchLimitReached,
    UnknownStatus,
    Truncated,
    AccessLoss,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub job_digest: Digest,
    pub attempt_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BatchEvidencePage {
    pub operation: String,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub page_number: u16,
    pub page_token_digest: Option<Digest>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BatchEvidence {
    pub plugin_version: String,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_revision: String,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub job_digest: Digest,
    pub attempt_digest: Digest,
    pub registration_digest: Digest,
    pub credential_revision: Revision,
    pub request_digest: Digest,
    pub pages: Vec<BatchEvidencePage>,
    pub list_summaries: Vec<JobSummary>,
    pub jobs: Vec<JobProjection>,
    pub provenance: ProviderProvenance,
    pub status: EvidenceStatus,
    pub partial_reason: Option<PartialReason>,
    pub access_loss: Option<AccessLossEvidence>,
    pub redaction: RedactionSummary,
    pub evidence_digest: Digest,
}

pub type AwsBatchJobResultEvidence = BatchEvidence;

#[derive(Serialize)]
struct EvidenceDigestInput<'a> {
    plugin_version: &'a str,
    contract_version: &'a str,
    contract_digest: &'a Digest,
    provider_revision: &'a str,
    provider_digest: &'a Digest,
    api_digest: &'a Digest,
    permission_digest: &'a Digest,
    scope_digest: &'a Digest,
    job_digest: &'a Digest,
    attempt_digest: &'a Digest,
    registration_digest: &'a Digest,
    credential_revision: Revision,
    request_digest: &'a Digest,
    pages: &'a [BatchEvidencePage],
    list_summaries: &'a [JobSummary],
    jobs: &'a [JobProjection],
    provenance: ProviderProvenance,
    status: EvidenceStatus,
    partial_reason: &'a Option<PartialReason>,
    access_loss: &'a Option<AccessLossEvidence>,
    redaction: &'a RedactionSummary,
}

impl BatchEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider_revision: String,
        provider_digest: Digest,
        api_digest: Digest,
        permission_digest: Digest,
        scope_digest: Digest,
        job_digest: Digest,
        attempt_digest: Digest,
        registration_digest: Digest,
        credential_revision: Revision,
        request_digest: Digest,
        pages: Vec<BatchEvidencePage>,
        list_summaries: Vec<JobSummary>,
        jobs: Vec<JobProjection>,
        provenance: ProviderProvenance,
        status: EvidenceStatus,
        partial_reason: Option<PartialReason>,
        access_loss: Option<AccessLossEvidence>,
    ) -> Result<Self, ModelError> {
        validate_text(&provider_revision, "provider revision")?;
        Revision::new(credential_revision.get())?;
        if provider_digest != crate::provider::provider_digest_for_revision(&provider_revision) {
            return Err(ModelError::InvalidValue {
                field: "provider digest",
            });
        }
        if api_digest != crate::api_digest() {
            return Err(ModelError::InvalidValue {
                field: "API digest",
            });
        }
        if permission_digest != crate::permission_digest() {
            return Err(ModelError::InvalidValue {
                field: "permission digest",
            });
        }
        if pages.is_empty() || pages.len() > usize::from(MAX_PAGES) {
            return Err(ModelError::BoundExceeded {
                field: "evidence pages",
            });
        }
        if list_summaries.len() > MAX_JOBS || jobs.len() > MAX_JOBS {
            return Err(ModelError::BoundExceeded {
                field: "evidence jobs",
            });
        }
        if status == EvidenceStatus::Complete && (partial_reason.is_some() || access_loss.is_some())
        {
            return Err(ModelError::InvalidValue {
                field: "complete evidence status",
            });
        }
        if status == EvidenceStatus::Partial && partial_reason.is_none() {
            return Err(ModelError::InvalidValue {
                field: "partial evidence reason",
            });
        }
        if status == EvidenceStatus::AccessLost && access_loss.is_none() {
            return Err(ModelError::InvalidValue {
                field: "access-loss evidence",
            });
        }
        for summary in &list_summaries {
            summary.validate()?;
        }
        for job in &jobs {
            job.validate()?;
        }
        if let Some(access_loss) = &access_loss {
            access_loss.validate()?;
        }
        let mut evidence = Self {
            plugin_version: AWS_BATCH_JOB_RESULT_PLUGIN_VERSION.to_owned(),
            contract_version: AWS_BATCH_JOB_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            provider_revision,
            provider_digest,
            api_digest,
            permission_digest,
            scope_digest,
            job_digest,
            attempt_digest,
            registration_digest,
            credential_revision,
            request_digest,
            pages,
            list_summaries,
            jobs,
            provenance,
            status,
            partial_reason,
            access_loss,
            redaction: RedactionSummary::default(),
            evidence_digest: Digest::from_text("pending-evidence-digest"),
        };
        evidence.evidence_digest = evidence.compute_digest()?;
        Ok(evidence)
    }

    fn compute_digest(&self) -> Result<Digest, ModelError> {
        digest_serializable(&EvidenceDigestInput {
            plugin_version: &self.plugin_version,
            contract_version: &self.contract_version,
            contract_digest: &self.contract_digest,
            provider_revision: &self.provider_revision,
            provider_digest: &self.provider_digest,
            api_digest: &self.api_digest,
            permission_digest: &self.permission_digest,
            scope_digest: &self.scope_digest,
            job_digest: &self.job_digest,
            attempt_digest: &self.attempt_digest,
            registration_digest: &self.registration_digest,
            credential_revision: self.credential_revision,
            request_digest: &self.request_digest,
            pages: &self.pages,
            list_summaries: &self.list_summaries,
            jobs: &self.jobs,
            provenance: self.provenance,
            status: self.status.clone(),
            partial_reason: &self.partial_reason,
            access_loss: &self.access_loss,
            redaction: &self.redaction,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.plugin_version != AWS_BATCH_JOB_RESULT_PLUGIN_VERSION
            || self.contract_version != AWS_BATCH_JOB_RESULT_CONTRACT_VERSION
            || self.contract_digest != crate::contract_digest()
            || validate_text(&self.provider_revision, "provider revision").is_err()
            || self.provider_digest
                != crate::provider::provider_digest_for_revision(&self.provider_revision)
            || self.api_digest != crate::api_digest()
            || self.permission_digest != crate::permission_digest()
            || self.pages.is_empty()
            || self.pages.len() > usize::from(MAX_PAGES)
            || self.list_summaries.len() > MAX_JOBS
            || self.jobs.len() > MAX_JOBS
            || self.redaction.raw_provider_payload_retained
            || self
                .list_summaries
                .iter()
                .any(|summary| summary.validate().is_err())
            || self.jobs.iter().any(|job| job.validate().is_err())
            || (self.status == EvidenceStatus::Complete
                && (self.partial_reason.is_some() || self.access_loss.is_some()))
            || (self.status == EvidenceStatus::Partial && self.partial_reason.is_none())
            || (self.status == EvidenceStatus::AccessLost && self.access_loss.is_none())
            || self
                .access_loss
                .as_ref()
                .is_some_and(|loss| loss.validate().is_err())
            || self.evidence_digest != self.compute_digest()?
        {
            return Err(ModelError::InvalidDigest {
                field: "batch evidence",
            });
        }
        Ok(())
    }

    pub fn validate_for(&self, scope: &AwsBatchScope) -> Result<(), ModelError> {
        scope.validate()?;
        self.validate()?;
        if self.scope_digest != scope.digest()
            || self.permission_digest != scope.permission_digest
            || self.permission_digest != crate::permission_digest()
            || self.job_digest != scope.job_digest()
            || self.attempt_digest != scope.attempt_digest()
        {
            return Err(ModelError::InvalidValue {
                field: "evidence scope fence",
            });
        }
        for job in &self.jobs {
            job.validate_against(scope)?;
        }
        Ok(())
    }

    pub fn digests(&self) -> EvidenceDigests {
        EvidenceDigests {
            plugin_version_digest: Digest::from_text(&self.plugin_version),
            contract_version_digest: Digest::from_text(&self.contract_version),
            contract_digest: self.contract_digest.clone(),
            provider_digest: self.provider_digest.clone(),
            api_digest: self.api_digest.clone(),
            permission_digest: self.permission_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            job_digest: self.job_digest.clone(),
            attempt_digest: self.attempt_digest.clone(),
            registration_digest: self.registration_digest.clone(),
            evidence_digest: self.evidence_digest.clone(),
        }
    }

    pub fn is_complete(&self) -> bool {
        self.status == EvidenceStatus::Complete
    }
}

pub fn permission_digest_from_names() -> Digest {
    Digest::from_fields(
        "hartevo.aws-batch-permissions/v1",
        &AWS_BATCH_IAM_PERMISSIONS.map(str::to_owned),
    )
}
