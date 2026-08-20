use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use zeroize::Zeroize;

use crate::error::{
    AwsEmrServerlessJobResultError, AwsEmrServerlessTransportError, Result, TransportErrorKind,
};
use crate::{
    LAYER1_PERMISSIONS, MAX_IDENTIFIER_BYTES, MAX_RESOURCE_UNITS, MAX_STATE_DETAILS_BYTES,
};

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value.as_ref())
    }

    pub fn from_parts(domain: &str, fields: &[(&str, String)]) -> Self {
        let mut bytes = Vec::new();
        append_field(&mut bytes, domain);
        for (name, value) in fields {
            append_field(&mut bytes, name);
            append_field(&mut bytes, value);
        }
        Self::from_bytes(&bytes)
    }

    pub fn parse(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if is_digest(&value) {
            Ok(Self(value))
        } else {
            Err(AwsEmrServerlessJobResultError::InvalidDigest)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(AwsEmrServerlessJobResultError::InvalidDigest)
        }
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

fn valid_text(value: &str, max_bytes: usize, allow_internal_whitespace: bool) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && (allow_internal_whitespace || !value.chars().any(char::is_whitespace))
}

fn valid_identifier(value: &str, max_bytes: usize) -> bool {
    valid_text(value, max_bytes, false)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn valid_lower_identifier(value: &str, max_bytes: usize) -> bool {
    valid_identifier(value, max_bytes) && value.bytes().all(|byte| !byte.is_ascii_uppercase())
}

fn valid_emr_identifier(value: &str, max_bytes: usize) -> bool {
    valid_text(value, max_bytes, false)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

macro_rules! identifier_type {
    ($name:ident, $field:literal, $validator:expr) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if ($validator)(&value) {
                    Ok(Self(value))
                } else {
                    Err(AwsEmrServerlessJobResultError::InvalidIdentifier { field: $field })
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub(crate) fn validate(&self) -> Result<()> {
                if ($validator)(&self.0) {
                    Ok(())
                } else {
                    Err(AwsEmrServerlessJobResultError::InvalidIdentifier { field: $field })
                }
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

identifier_type!(ProjectId, "project", |value: &str| {
    valid_identifier(value, MAX_IDENTIFIER_BYTES)
});
identifier_type!(MissionId, "mission", |value: &str| {
    valid_identifier(value, MAX_IDENTIFIER_BYTES)
});
identifier_type!(WorkProductId, "work-product", |value: &str| {
    valid_identifier(value, MAX_IDENTIFIER_BYTES)
});
identifier_type!(ApplicationId, "application", |value: &str| {
    valid_emr_identifier(value, 64)
});
identifier_type!(JobRunId, "job-run", |value: &str| {
    valid_emr_identifier(value, 64)
});
identifier_type!(ReleaseLabel, "release-label", |value: &str| {
    valid_identifier(value, 64)
});

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AwsAccountId(String);

impl AwsAccountId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.len() == 12 && value.bytes().all(|byte| byte.is_ascii_digit()) {
            Ok(Self(value))
        } else {
            Err(AwsEmrServerlessJobResultError::InvalidIdentifier { field: "account" })
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-emr-serverless-account/v1",
            &[("account", self.0.clone())],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        Self::new(self.0.clone()).map(|_| ())
    }
}

impl fmt::Debug for AwsAccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("AwsAccountId")
            .field(&self.digest())
            .finish()
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AwsRegion(String);

impl AwsRegion {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into().to_ascii_lowercase();
        if valid_lower_identifier(&value, 64) {
            Ok(Self(value))
        } else {
            Err(AwsEmrServerlessJobResultError::InvalidIdentifier { field: "region" })
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        Self::new(self.0.clone()).map(|_| ())
    }
}

impl fmt::Debug for AwsRegion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("AwsRegion").field(&self.0).finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self> {
        if value == 0 {
            Err(AwsEmrServerlessJobResultError::InvalidScope)
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectScope {
    id: ProjectId,
    revision: Revision,
}

impl ProjectScope {
    pub fn new(id: ProjectId, revision: Revision) -> Self {
        Self { id, revision }
    }

    pub fn id(&self) -> &ProjectId {
        &self.id
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-emr-serverless-project-scope/v1",
            &[
                ("id", self.id.as_str().to_owned()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }

    fn validate(&self) -> Result<()> {
        self.id.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionScope {
    id: MissionId,
    revision: Revision,
    valid_until: DateTime<Utc>,
}

impl MissionScope {
    pub fn new(id: MissionId, revision: Revision, valid_until: DateTime<Utc>) -> Self {
        Self {
            id,
            revision,
            valid_until,
        }
    }

    pub fn id(&self) -> &MissionId {
        &self.id
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub const fn valid_until(&self) -> DateTime<Utc> {
        self.valid_until
    }

    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now >= self.valid_until
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-emr-serverless-mission-scope/v1",
            &[
                ("id", self.id.as_str().to_owned()),
                ("revision", self.revision.get().to_string()),
                ("valid_until", self.valid_until.to_rfc3339()),
            ],
        )
    }

    fn validate(&self) -> Result<()> {
        self.id.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkProductScope {
    id: WorkProductId,
    revision: Revision,
}

impl WorkProductScope {
    pub fn new(id: WorkProductId, revision: Revision) -> Self {
        Self { id, revision }
    }

    pub fn id(&self) -> &WorkProductId {
        &self.id
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-emr-serverless-work-product-scope/v1",
            &[
                ("id", self.id.as_str().to_owned()),
                ("revision", self.revision.get().to_string()),
            ],
        )
    }

    fn validate(&self) -> Result<()> {
        self.id.validate()
    }
}

/// An opaque handle to a SigV4 credential reference.
///
/// The handle is intentionally neither `Serialize` nor `Deserialize`. It is
/// not exposed through an accessor, and its `Debug` representation contains
/// only a deterministic reference digest.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    handle: String,
    scope_binding_digest: Digest,
    credential_revision: Revision,
}

impl SecretReference {
    pub fn new(
        handle: impl Into<String>,
        scope_binding_digest: &Digest,
        credential_revision: Revision,
    ) -> Result<Self> {
        let handle = handle.into();
        if !valid_text(&handle, MAX_IDENTIFIER_BYTES, false)
            || handle.bytes().any(|byte| !byte.is_ascii_graphic())
        {
            return Err(AwsEmrServerlessJobResultError::InvalidSecretReference);
        }
        scope_binding_digest.validate()?;
        Ok(Self {
            handle,
            scope_binding_digest: scope_binding_digest.clone(),
            credential_revision,
        })
    }

    pub fn scope_binding_digest(&self) -> &Digest {
        &self.scope_binding_digest
    }

    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    pub fn reference_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-emr-serverless-secret-reference/v1",
            &[
                ("handle", self.handle.clone()),
                ("scope", self.scope_binding_digest.as_str().to_owned()),
                (
                    "credential_revision",
                    self.credential_revision.get().to_string(),
                ),
            ],
        )
    }

    pub(crate) fn validate(&self, expected_scope_binding: &Digest) -> Result<()> {
        if self.scope_binding_digest != *expected_scope_binding {
            return Err(AwsEmrServerlessJobResultError::ScopeMismatch);
        }
        if !valid_text(&self.handle, MAX_IDENTIFIER_BYTES, false)
            || self.handle.bytes().any(|byte| !byte.is_ascii_graphic())
        {
            return Err(AwsEmrServerlessJobResultError::InvalidSecretReference);
        }
        self.scope_binding_digest.validate()
    }
}

impl Drop for SecretReference {
    fn drop(&mut self) {
        self.handle.zeroize();
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("reference_digest", &self.reference_digest())
            .field("credential_revision", &self.credential_revision)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsEmrServerlessScopeInput {
    account_id: AwsAccountId,
    region: AwsRegion,
    application_id: ApplicationId,
    job_run_id: JobRunId,
    attempt: u32,
    execution_role_digest: Digest,
    release_label: ReleaseLabel,
    job_driver_digest: Digest,
    project: ProjectScope,
    mission: MissionScope,
    work_product: WorkProductScope,
}

impl AwsEmrServerlessScopeInput {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: AwsAccountId,
        region: AwsRegion,
        application_id: ApplicationId,
        job_run_id: JobRunId,
        attempt: u32,
        execution_role_digest: Digest,
        release_label: ReleaseLabel,
        job_driver_digest: Digest,
        project: ProjectScope,
        mission: MissionScope,
        work_product: WorkProductScope,
    ) -> Result<Self> {
        let input = Self {
            account_id,
            region,
            application_id,
            job_run_id,
            attempt,
            execution_role_digest,
            release_label,
            job_driver_digest,
            project,
            mission,
            work_product,
        };
        input.validate()?;
        Ok(input)
    }

    pub fn base_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-emr-serverless-scope-input/v1",
            &[
                ("account", self.account_id.as_str().to_owned()),
                ("region", self.region.as_str().to_owned()),
                ("application", self.application_id.as_str().to_owned()),
                ("job_run", self.job_run_id.as_str().to_owned()),
                ("attempt", self.attempt.to_string()),
                (
                    "execution_role",
                    self.execution_role_digest.as_str().to_owned(),
                ),
                ("release_label", self.release_label.as_str().to_owned()),
                ("job_driver", self.job_driver_digest.as_str().to_owned()),
                ("project", self.project.digest().as_str().to_owned()),
                ("mission", self.mission.digest().as_str().to_owned()),
                (
                    "work_product",
                    self.work_product.digest().as_str().to_owned(),
                ),
            ],
        )
    }

    pub fn account_id(&self) -> &AwsAccountId {
        &self.account_id
    }

    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    pub fn application_id(&self) -> &ApplicationId {
        &self.application_id
    }

    pub fn job_run_id(&self) -> &JobRunId {
        &self.job_run_id
    }

    pub const fn attempt(&self) -> u32 {
        self.attempt
    }

    pub fn execution_role_digest(&self) -> &Digest {
        &self.execution_role_digest
    }

    pub fn release_label(&self) -> &ReleaseLabel {
        &self.release_label
    }

    pub fn job_driver_digest(&self) -> &Digest {
        &self.job_driver_digest
    }

    pub fn project(&self) -> &ProjectScope {
        &self.project
    }

    pub fn mission(&self) -> &MissionScope {
        &self.mission
    }

    pub fn work_product(&self) -> &WorkProductScope {
        &self.work_product
    }

    fn validate(&self) -> Result<()> {
        self.account_id.validate()?;
        self.region.validate()?;
        self.application_id.validate()?;
        self.job_run_id.validate()?;
        if self.attempt == 0 {
            return Err(AwsEmrServerlessJobResultError::InvalidScope);
        }
        self.execution_role_digest.validate()?;
        self.release_label.validate()?;
        self.job_driver_digest.validate()?;
        self.project.validate()?;
        self.mission.validate()?;
        self.work_product.validate()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AwsEmrServerlessJobResultScope {
    input: AwsEmrServerlessScopeInput,
    secret_reference: SecretReference,
    scope_digest: Digest,
}

impl AwsEmrServerlessJobResultScope {
    pub fn new(
        input: AwsEmrServerlessScopeInput,
        secret_reference: SecretReference,
    ) -> Result<Self> {
        input.validate()?;
        secret_reference.validate(&input.base_digest())?;
        let scope_digest = Digest::from_parts(
            "aws-emr-serverless-job-result-scope/v1",
            &[
                ("base", input.base_digest().as_str().to_owned()),
                (
                    "secret",
                    secret_reference.reference_digest().as_str().to_owned(),
                ),
            ],
        );
        Ok(Self {
            input,
            secret_reference,
            scope_digest,
        })
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn base_digest(&self) -> Digest {
        self.input.base_digest()
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn account_id(&self) -> &AwsAccountId {
        self.input.account_id()
    }

    pub fn region(&self) -> &AwsRegion {
        self.input.region()
    }

    pub fn application_id(&self) -> &ApplicationId {
        self.input.application_id()
    }

    pub fn job_run_id(&self) -> &JobRunId {
        self.input.job_run_id()
    }

    pub const fn attempt(&self) -> u32 {
        self.input.attempt()
    }

    pub fn execution_role_digest(&self) -> &Digest {
        self.input.execution_role_digest()
    }

    pub fn release_label(&self) -> &ReleaseLabel {
        self.input.release_label()
    }

    pub fn job_driver_digest(&self) -> &Digest {
        self.input.job_driver_digest()
    }

    pub fn project(&self) -> &ProjectScope {
        self.input.project()
    }

    pub fn mission(&self) -> &MissionScope {
        self.input.mission()
    }

    pub fn work_product(&self) -> &WorkProductScope {
        self.input.work_product()
    }

    pub fn project_digest(&self) -> Digest {
        self.project().digest()
    }

    pub fn mission_digest(&self) -> Digest {
        self.mission().digest()
    }

    pub fn work_product_digest(&self) -> Digest {
        self.work_product().digest()
    }

    pub fn mission_revision(&self) -> Revision {
        self.mission().revision()
    }

    pub fn work_product_revision(&self) -> Revision {
        self.work_product().revision()
    }

    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        self.mission().is_expired(now)
    }

    pub fn validate(&self) -> Result<()> {
        let expected = Self::new(self.input.clone(), self.secret_reference.clone())?;
        if expected.scope_digest != self.scope_digest {
            return Err(AwsEmrServerlessJobResultError::TamperedEvidence);
        }
        Ok(())
    }
}

impl fmt::Debug for AwsEmrServerlessJobResultScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsEmrServerlessJobResultScope")
            .field("account_digest", &self.account_id().digest())
            .field("region", &self.region())
            .field("application_id", &self.application_id())
            .field("job_run_id", &self.job_run_id())
            .field("attempt", &self.attempt())
            .field("execution_role_digest", &self.execution_role_digest())
            .field("release_label", &self.release_label())
            .field("job_driver_digest", &self.job_driver_digest())
            .field("project_digest", &self.project_digest())
            .field("mission_digest", &self.mission_digest())
            .field("work_product_digest", &self.work_product_digest())
            .field("scope_digest", &self.scope_digest)
            .field("secret_reference", &self.secret_reference)
            .finish()
    }
}

pub fn layer1_permission_digest() -> Digest {
    Digest::from_parts(
        "aws-emr-serverless-layer1-permissions/v1",
        &LAYER1_PERMISSIONS
            .iter()
            .map(|permission| ("permission", (*permission).to_owned()))
            .collect::<Vec<_>>(),
    )
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApplicationState {
    Created,
    Starting,
    Started,
    Stopped,
    Terminated,
    Failed,
    ProviderUnknown,
}

impl ApplicationState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "CREATED",
            Self::Starting => "STARTING",
            Self::Started => "STARTED",
            Self::Stopped => "STOPPED",
            Self::Terminated => "TERMINATED",
            Self::Failed => "FAILED",
            Self::ProviderUnknown => "PROVIDER_UNKNOWN",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum JobRunMode {
    Batch,
    Streaming,
    ProviderUnknown,
}

impl JobRunMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Batch => "BATCH",
            Self::Streaming => "STREAMING",
            Self::ProviderUnknown => "PROVIDER_UNKNOWN",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum JobRunState {
    Submitted,
    Pending,
    Scheduled,
    Queued,
    Running,
    Success,
    Failed,
    Cancelling,
    Cancelled,
    Partial,
    Expired,
    AccessLost,
    ProviderUnknown,
    Tampered,
    Revoked,
}

impl JobRunState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "SUBMITTED",
            Self::Pending => "PENDING",
            Self::Scheduled => "SCHEDULED",
            Self::Queued => "QUEUED",
            Self::Running => "RUNNING",
            Self::Success => "SUCCESS",
            Self::Failed => "FAILED",
            Self::Cancelling => "CANCELLING",
            Self::Cancelled => "CANCELLED",
            Self::Partial => "PARTIAL",
            Self::Expired => "EXPIRED",
            Self::AccessLost => "ACCESS_LOST",
            Self::ProviderUnknown => "PROVIDER_UNKNOWN",
            Self::Tampered => "TAMPERED",
            Self::Revoked => "REVOKED",
        }
    }

    pub const fn lifecycle_rank(self) -> Option<u8> {
        match self {
            Self::Submitted => Some(1),
            Self::Pending => Some(2),
            Self::Scheduled => Some(3),
            Self::Queued => Some(4),
            Self::Running => Some(5),
            Self::Success | Self::Failed | Self::Cancelling | Self::Cancelled => Some(6),
            Self::Partial
            | Self::Expired
            | Self::AccessLost
            | Self::ProviderUnknown
            | Self::Tampered
            | Self::Revoked => None,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct StateDetails(String);

impl StateDetails {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.len() <= MAX_STATE_DETAILS_BYTES
            && !value.chars().any(char::is_control)
            && value.trim() == value
        {
            Ok(Self(value))
        } else {
            Err(AwsEmrServerlessJobResultError::InvalidText {
                field: "state-details",
            })
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-emr-serverless-state-details/v1",
            &[("details", self.0.clone())],
        )
    }
}

impl fmt::Debug for StateDetails {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StateDetails")
            .field("digest", &self.digest())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceMetadata {
    pub worker_count: u32,
    pub vcpu_hours_milli: u64,
    pub memory_gb_hours_milli: u64,
    pub storage_gb_hours_milli: u64,
    pub cost_micros: Option<u64>,
}

impl ResourceMetadata {
    pub fn new(
        worker_count: u32,
        vcpu_hours_milli: u64,
        memory_gb_hours_milli: u64,
        storage_gb_hours_milli: u64,
        cost_micros: Option<u64>,
    ) -> Result<Self> {
        let value = Self {
            worker_count,
            vcpu_hours_milli,
            memory_gb_hours_milli,
            storage_gb_hours_milli,
            cost_micros,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-emr-serverless-resource-metadata/v1",
            &[
                ("workers", self.worker_count.to_string()),
                ("vcpu", self.vcpu_hours_milli.to_string()),
                ("memory", self.memory_gb_hours_milli.to_string()),
                ("storage", self.storage_gb_hours_milli.to_string()),
                (
                    "cost",
                    self.cost_micros
                        .map_or_else(|| "none".to_owned(), |value| value.to_string()),
                ),
            ],
        )
    }

    fn validate(&self) -> Result<()> {
        if u64::from(self.worker_count) > MAX_RESOURCE_UNITS
            || self.vcpu_hours_milli > MAX_RESOURCE_UNITS
            || self.memory_gb_hours_milli > MAX_RESOURCE_UNITS
            || self.storage_gb_hours_milli > MAX_RESOURCE_UNITS
            || self
                .cost_micros
                .is_some_and(|value| value > crate::MAX_COST_MICROS)
        {
            return Err(AwsEmrServerlessJobResultError::ResponseTooLarge);
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ApplicationRecord {
    application_id: ApplicationId,
    state: ApplicationState,
    release_label: ReleaseLabel,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    application_digest: Digest,
}

impl ApplicationRecord {
    pub fn new(
        application_id: ApplicationId,
        state: ApplicationState,
        release_label: ReleaseLabel,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    ) -> Result<Self> {
        if updated_at < created_at {
            return Err(AwsEmrServerlessJobResultError::InvalidResponseShape);
        }
        let mut value = Self {
            application_id,
            state,
            release_label,
            created_at,
            updated_at,
            application_digest: Digest::from_text("unsealed-application"),
        };
        value.application_digest = value.calculate_digest();
        Ok(value)
    }

    pub fn application_id(&self) -> &ApplicationId {
        &self.application_id
    }

    pub const fn state(&self) -> ApplicationState {
        self.state
    }

    pub fn release_label(&self) -> &ReleaseLabel {
        &self.release_label
    }

    pub const fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    pub const fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }

    pub fn application_digest(&self) -> &Digest {
        &self.application_digest
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-emr-serverless-application/v1",
            &[
                ("application", self.application_id.as_str().to_owned()),
                ("state", self.state.as_str().to_owned()),
                ("release", self.release_label.as_str().to_owned()),
                ("created", self.created_at.to_rfc3339()),
                ("updated", self.updated_at.to_rfc3339()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.application_id.validate()?;
        self.release_label.validate()?;
        if self.updated_at < self.created_at || self.application_digest != self.calculate_digest() {
            return Err(AwsEmrServerlessJobResultError::TamperedEvidence);
        }
        Ok(())
    }
}

impl fmt::Debug for ApplicationRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApplicationRecord")
            .field("application_digest", &self.application_digest)
            .field("state", &self.state)
            .field("release_label", &self.release_label)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobRunRecordInput {
    pub application_id: ApplicationId,
    pub job_run_id: JobRunId,
    pub attempt: u32,
    pub state: JobRunState,
    pub mode: JobRunMode,
    pub release_label: ReleaseLabel,
    pub execution_role_digest: Digest,
    pub job_driver_digest: Digest,
    pub created_at: DateTime<Utc>,
    pub attempt_created_at: DateTime<Utc>,
    pub attempt_updated_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub ended_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
    pub queued_duration_millis: u64,
    pub total_execution_duration_seconds: Option<u64>,
    pub state_details: Option<StateDetails>,
    pub resources: ResourceMetadata,
}

#[derive(Clone, Eq, PartialEq)]
pub struct JobRunRecord {
    input: JobRunRecordInput,
    job_run_digest: Digest,
}

impl JobRunRecord {
    pub fn new(input: JobRunRecordInput) -> Result<Self> {
        input.application_id.validate()?;
        input.job_run_id.validate()?;
        input.release_label.validate()?;
        input.execution_role_digest.validate()?;
        input.job_driver_digest.validate()?;
        if input.attempt == 0
            || input.attempt_updated_at < input.attempt_created_at
            || input.attempt_created_at < input.created_at
            || input.updated_at < input.attempt_updated_at
            || input
                .started_at
                .is_some_and(|value| value < input.attempt_created_at)
            || input
                .ended_at
                .is_some_and(|value| input.started_at.is_some_and(|started| value < started))
            || input
                .total_execution_duration_seconds
                .is_some_and(|value| value > 10 * 365 * 24 * 60 * 60)
        {
            return Err(AwsEmrServerlessJobResultError::InvalidResponseShape);
        }
        input.resources.validate()?;
        let mut record = Self {
            input,
            job_run_digest: Digest::from_text("unsealed-job-run"),
        };
        record.job_run_digest = record.calculate_digest();
        Ok(record)
    }

    pub fn application_id(&self) -> &ApplicationId {
        &self.input.application_id
    }

    pub fn job_run_id(&self) -> &JobRunId {
        &self.input.job_run_id
    }

    pub const fn attempt(&self) -> u32 {
        self.input.attempt
    }

    pub const fn state(&self) -> JobRunState {
        self.input.state
    }

    pub const fn mode(&self) -> JobRunMode {
        self.input.mode
    }

    pub fn release_label(&self) -> &ReleaseLabel {
        &self.input.release_label
    }

    pub fn execution_role_digest(&self) -> &Digest {
        &self.input.execution_role_digest
    }

    pub fn job_driver_digest(&self) -> &Digest {
        &self.input.job_driver_digest
    }

    pub const fn created_at(&self) -> DateTime<Utc> {
        self.input.created_at
    }

    pub const fn attempt_created_at(&self) -> DateTime<Utc> {
        self.input.attempt_created_at
    }

    pub const fn attempt_updated_at(&self) -> DateTime<Utc> {
        self.input.attempt_updated_at
    }

    pub const fn started_at(&self) -> Option<DateTime<Utc>> {
        self.input.started_at
    }

    pub const fn ended_at(&self) -> Option<DateTime<Utc>> {
        self.input.ended_at
    }

    pub const fn updated_at(&self) -> DateTime<Utc> {
        self.input.updated_at
    }

    pub const fn queued_duration_millis(&self) -> u64 {
        self.input.queued_duration_millis
    }

    pub const fn total_execution_duration_seconds(&self) -> Option<u64> {
        self.input.total_execution_duration_seconds
    }

    pub fn state_details_digest(&self) -> Option<Digest> {
        self.input.state_details.as_ref().map(StateDetails::digest)
    }

    pub fn resources(&self) -> &ResourceMetadata {
        &self.input.resources
    }

    pub fn job_run_digest(&self) -> &Digest {
        &self.job_run_digest
    }

    pub fn attempt_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-emr-serverless-attempt/v1",
            &[
                ("job_run", self.job_run_id().as_str().to_owned()),
                ("attempt", self.attempt().to_string()),
                ("record", self.job_run_digest.as_str().to_owned()),
            ],
        )
    }

    pub fn state_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-emr-serverless-state/v1",
            &[
                ("state", self.state().as_str().to_owned()),
                ("updated", self.updated_at().to_rfc3339()),
                (
                    "details",
                    self.state_details_digest()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
            ],
        )
    }

    pub fn result_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-emr-serverless-result/v1",
            &[
                ("job_run", self.job_run_digest.as_str().to_owned()),
                ("state", self.state_digest().as_str().to_owned()),
                ("resource", self.resources().digest().as_str().to_owned()),
                (
                    "duration",
                    self.total_execution_duration_seconds()
                        .map_or_else(String::new, |value| value.to_string()),
                ),
            ],
        )
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-emr-serverless-job-run/v1",
            &[
                ("application", self.application_id().as_str().to_owned()),
                ("job_run", self.job_run_id().as_str().to_owned()),
                ("attempt", self.attempt().to_string()),
                ("state", self.state().as_str().to_owned()),
                ("mode", self.mode().as_str().to_owned()),
                ("release", self.release_label().as_str().to_owned()),
                (
                    "execution_role",
                    self.execution_role_digest().as_str().to_owned(),
                ),
                ("job_driver", self.job_driver_digest().as_str().to_owned()),
                ("created", self.created_at().to_rfc3339()),
                ("attempt_created", self.attempt_created_at().to_rfc3339()),
                ("attempt_updated", self.attempt_updated_at().to_rfc3339()),
                (
                    "started",
                    self.started_at()
                        .map_or_else(String::new, |value| value.to_rfc3339()),
                ),
                (
                    "ended",
                    self.ended_at()
                        .map_or_else(String::new, |value| value.to_rfc3339()),
                ),
                ("updated", self.updated_at().to_rfc3339()),
                ("queued_ms", self.queued_duration_millis().to_string()),
                (
                    "duration_s",
                    self.total_execution_duration_seconds()
                        .map_or_else(String::new, |value| value.to_string()),
                ),
                (
                    "state_details",
                    self.state_details_digest()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                ("resource", self.resources().digest().as_str().to_owned()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.job_run_digest != self.calculate_digest() {
            return Err(AwsEmrServerlessJobResultError::TamperedEvidence);
        }
        self.input.resources.validate()
    }
}

impl fmt::Debug for JobRunRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JobRunRecord")
            .field("job_run_digest", &self.job_run_digest)
            .field("attempt", &self.attempt())
            .field("state", &self.state())
            .field("mode", &self.mode())
            .field("release_label", &self.release_label())
            .field("execution_role_digest", &self.execution_role_digest())
            .field("job_driver_digest", &self.job_driver_digest())
            .field("created_at", &self.created_at())
            .field("attempt_created_at", &self.attempt_created_at())
            .field("attempt_updated_at", &self.attempt_updated_at())
            .field("started_at", &self.started_at())
            .field("ended_at", &self.ended_at())
            .field("updated_at", &self.updated_at())
            .field("queued_duration_millis", &self.queued_duration_millis())
            .field(
                "total_execution_duration_seconds",
                &self.total_execution_duration_seconds(),
            )
            .field("state_details", &self.input.state_details)
            .field("resources", &self.resources())
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobRunSummary {
    application_id: ApplicationId,
    job_run_id: JobRunId,
    attempt: u32,
    state: JobRunState,
    mode: JobRunMode,
    updated_at: DateTime<Utc>,
    summary_digest: Digest,
}

impl JobRunSummary {
    pub fn from_record(record: &JobRunRecord) -> Self {
        let mut summary = Self {
            application_id: record.application_id().clone(),
            job_run_id: record.job_run_id().clone(),
            attempt: record.attempt(),
            state: record.state(),
            mode: record.mode(),
            updated_at: record.updated_at(),
            summary_digest: Digest::from_text("unsealed-job-run-summary"),
        };
        summary.summary_digest = summary.calculate_digest();
        summary
    }

    pub fn application_id(&self) -> &ApplicationId {
        &self.application_id
    }

    pub fn job_run_id(&self) -> &JobRunId {
        &self.job_run_id
    }

    pub const fn attempt(&self) -> u32 {
        self.attempt
    }

    pub const fn state(&self) -> JobRunState {
        self.state
    }

    pub const fn mode(&self) -> JobRunMode {
        self.mode
    }

    pub const fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }

    pub fn summary_digest(&self) -> &Digest {
        &self.summary_digest
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-emr-serverless-job-run-summary/v1",
            &[
                ("application", self.application_id.as_str().to_owned()),
                ("job_run", self.job_run_id.as_str().to_owned()),
                ("attempt", self.attempt.to_string()),
                ("state", self.state.as_str().to_owned()),
                ("mode", self.mode.as_str().to_owned()),
                ("updated", self.updated_at.to_rfc3339()),
            ],
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.application_id.validate()?;
        self.job_run_id.validate()?;
        if self.attempt == 0 || self.summary_digest != self.calculate_digest() {
            return Err(AwsEmrServerlessJobResultError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct OpaqueNextToken {
    value: String,
    binding_digest: Digest,
}

impl OpaqueNextToken {
    pub fn new(value: impl Into<String>, binding_digest: &Digest) -> Result<Self> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 1024
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'=' | b'-'))
        {
            return Err(AwsEmrServerlessJobResultError::InvalidRequest);
        }
        binding_digest.validate()?;
        Ok(Self {
            value,
            binding_digest: binding_digest.clone(),
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-emr-serverless-next-token/v1",
            &[
                ("value", self.value.clone()),
                ("binding", self.binding_digest.as_str().to_owned()),
            ],
        )
    }

    pub fn binding_digest(&self) -> &Digest {
        &self.binding_digest
    }
}

impl fmt::Debug for OpaqueNextToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueNextToken")
            .field("digest", &self.digest())
            .field("binding_digest", &self.binding_digest)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialReason {
    PageCap,
    MissingExactJobRun,
    ProviderPartial,
    Timeout,
    ResponseCap,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderErrorEvidence {
    pub operation: String,
    pub kind: String,
    pub status_code: Option<u16>,
    pub error_digest: Digest,
}

impl ProviderErrorEvidence {
    pub fn new(operation: impl Into<String>, error: AwsEmrServerlessTransportError) -> Self {
        let operation = operation.into();
        let kind = error.kind().as_str().to_owned();
        let status_code = error.status_code();
        let error_digest = Digest::from_parts(
            "aws-emr-serverless-provider-error/v1",
            &[
                ("operation", operation.clone()),
                ("kind", kind.clone()),
                (
                    "status",
                    status_code.map_or_else(String::new, |value| value.to_string()),
                ),
            ],
        );
        Self {
            operation,
            kind,
            status_code,
            error_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDigests {
    pub application_digest: Digest,
    pub job_run_digest: Digest,
    pub attempt_digest: Digest,
    pub state_digest: Digest,
    pub resource_digest: Digest,
    pub result_digest: Digest,
    pub state_details_digest: Option<Digest>,
    pub provider_response_digest: Digest,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JobRunEvidence {
    pub scope_digest: Digest,
    pub project_digest: Digest,
    pub mission_digest: Digest,
    pub work_product_digest: Digest,
    pub mission_revision: Revision,
    pub work_product_revision: Revision,
    pub application_digest: Digest,
    pub application_state: ApplicationState,
    pub attempt: u32,
    pub attempt_digest: Digest,
    pub observed_state: JobRunState,
    pub status: JobRunState,
    pub mode: JobRunMode,
    pub release_label_digest: Digest,
    pub execution_role_digest: Digest,
    pub job_driver_digest: Digest,
    pub created_at: DateTime<Utc>,
    pub attempt_created_at: DateTime<Utc>,
    pub attempt_updated_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub ended_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
    pub queued_duration_millis: u64,
    pub total_execution_duration_seconds: Option<u64>,
    pub resource: ResourceMetadata,
    pub state_details_digest: Option<Digest>,
    pub digests: EvidenceDigests,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub truth_authority: bool,
    pub consent_authority: bool,
    pub effect_authority: bool,
    pub verification_authority: bool,
    pub outcome_authority: bool,
    pub work_product_adopted: bool,
}

impl JobRunEvidence {
    pub(crate) fn from_records(
        scope: &AwsEmrServerlessJobResultScope,
        application: &ApplicationRecord,
        job_run: &JobRunRecord,
        provider_response_digest: Digest,
        status: JobRunState,
        provenance: TransportProvenance,
    ) -> Self {
        let state_details_digest = job_run.state_details_digest();
        let mut digests = EvidenceDigests {
            application_digest: application.application_digest().clone(),
            job_run_digest: job_run.job_run_digest().clone(),
            attempt_digest: job_run.attempt_digest(),
            state_digest: job_run.state_digest(),
            resource_digest: job_run.resources().digest(),
            result_digest: job_run.result_digest(),
            state_details_digest: state_details_digest.clone(),
            provider_response_digest,
            evidence_digest: Digest::from_text("unsealed-evidence"),
        };
        let mut evidence = Self {
            scope_digest: scope.scope_digest().clone(),
            project_digest: scope.project_digest(),
            mission_digest: scope.mission_digest(),
            work_product_digest: scope.work_product_digest(),
            mission_revision: scope.mission_revision(),
            work_product_revision: scope.work_product_revision(),
            application_digest: application.application_digest().clone(),
            application_state: application.state(),
            attempt: job_run.attempt(),
            attempt_digest: job_run.attempt_digest(),
            observed_state: job_run.state(),
            status,
            mode: job_run.mode(),
            release_label_digest: Digest::from_parts(
                "aws-emr-serverless-release-label/v1",
                &[("release", job_run.release_label().as_str().to_owned())],
            ),
            execution_role_digest: job_run.execution_role_digest().clone(),
            job_driver_digest: job_run.job_driver_digest().clone(),
            created_at: job_run.created_at(),
            attempt_created_at: job_run.attempt_created_at(),
            attempt_updated_at: job_run.attempt_updated_at(),
            started_at: job_run.started_at(),
            ended_at: job_run.ended_at(),
            updated_at: job_run.updated_at(),
            queued_duration_millis: job_run.queued_duration_millis(),
            total_execution_duration_seconds: job_run.total_execution_duration_seconds(),
            resource: job_run.resources().clone(),
            state_details_digest,
            digests: digests.clone(),
            provenance,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            truth_authority: false,
            consent_authority: false,
            effect_authority: false,
            verification_authority: false,
            outcome_authority: false,
            work_product_adopted: false,
        };
        digests.evidence_digest = evidence.calculate_digest();
        evidence.digests = digests;
        evidence
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-emr-serverless-evidence/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("application", self.application_digest.as_str().to_owned()),
                ("attempt", self.attempt_digest.as_str().to_owned()),
                ("observed_state", self.observed_state.as_str().to_owned()),
                ("status", self.status.as_str().to_owned()),
                ("mode", self.mode.as_str().to_owned()),
                ("release", self.release_label_digest.as_str().to_owned()),
                (
                    "execution_role",
                    self.execution_role_digest.as_str().to_owned(),
                ),
                ("job_driver", self.job_driver_digest.as_str().to_owned()),
                ("created", self.created_at.to_rfc3339()),
                ("attempt_created", self.attempt_created_at.to_rfc3339()),
                ("attempt_updated", self.attempt_updated_at.to_rfc3339()),
                (
                    "started",
                    self.started_at
                        .map_or_else(String::new, |value| value.to_rfc3339()),
                ),
                (
                    "ended",
                    self.ended_at
                        .map_or_else(String::new, |value| value.to_rfc3339()),
                ),
                ("updated", self.updated_at.to_rfc3339()),
                (
                    "duration",
                    self.total_execution_duration_seconds
                        .map_or_else(String::new, |value| value.to_string()),
                ),
                ("resource", self.resource.digest().as_str().to_owned()),
                (
                    "details",
                    self.state_details_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "provider_response",
                    self.digests.provider_response_digest.as_str().to_owned(),
                ),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.truth_authority
            || self.consent_authority
            || self.effect_authority
            || self.verification_authority
            || self.outcome_authority
            || self.work_product_adopted
            || self.digests.evidence_digest != self.calculate_digest()
        {
            return Err(AwsEmrServerlessJobResultError::TamperedEvidence);
        }
        if self.resource.digest() != self.digests.resource_digest
            || self.state_details_digest != self.digests.state_details_digest
        {
            return Err(AwsEmrServerlessJobResultError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::Recording => "recording",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "blocked_env",
        }
    }

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

pub fn validate_monotonic_lifecycle(
    previous: Option<JobRunState>,
    current: JobRunState,
) -> Result<()> {
    if let (Some(_previous), Some(previous_rank), Some(current_rank)) = (
        previous,
        previous.and_then(JobRunState::lifecycle_rank),
        current.lifecycle_rank(),
    ) && current_rank < previous_rank
    {
        return Err(AwsEmrServerlessJobResultError::LifecycleRegression);
    }
    Ok(())
}

pub(crate) fn response_digest(domain: &str, values: &[(&str, String)]) -> Digest {
    Digest::from_parts(domain, values)
}

pub(crate) fn provider_error_evidence(
    operation: &str,
    error: AwsEmrServerlessTransportError,
) -> ProviderErrorEvidence {
    ProviderErrorEvidence::new(operation, error)
}

pub(crate) fn permissions_digest() -> Digest {
    layer1_permission_digest()
}

pub(crate) fn _transport_kind_is_known(kind: TransportErrorKind) -> bool {
    matches!(
        kind,
        TransportErrorKind::BlockedEnv
            | TransportErrorKind::BadRequest
            | TransportErrorKind::Unauthorized
            | TransportErrorKind::Forbidden
            | TransportErrorKind::NotFound
            | TransportErrorKind::RateLimited
            | TransportErrorKind::ServerError
            | TransportErrorKind::Timeout
            | TransportErrorKind::Partial
            | TransportErrorKind::InvalidResponse
    )
}
