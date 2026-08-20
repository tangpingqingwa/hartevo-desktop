//! Typed, bounded AWS Glue job-run scope and evidence models.
//!
//! The public model has no representation for a Glue script, command,
//! argument map, CloudWatch log, data row, credential, or native request body.
//! Those values therefore cannot cross this Layer-1 boundary accidentally.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    AWS_GLUE_JOB_RESULT_CONSUMER_ID, AWS_GLUE_JOB_RESULT_CONTRACT_VERSION,
    AWS_GLUE_JOB_RESULT_SCHEMA_VERSION, AWS_GLUE_JOB_RESULT_SERVICE_ID,
};

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_JOB_NAME_BYTES: usize = 255;
pub const MAX_RUN_ID_BYTES: usize = 255;
pub const MAX_CURSOR_BYTES: usize = 4 * 1024;
pub const MAX_RUNS: u32 = 256;
pub const MAX_PAGE_SIZE: u32 = 100;
pub const MAX_PAGES: u8 = 16;
pub const MAX_TIMEOUT_SECONDS: u32 = 24 * 60 * 60;
pub const MAX_COUNTER: u64 = 10_000_000_000;
pub const MAX_CAPACITY_MILLI: u32 = 1_000_000;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ModelError {
    #[error("identifier is empty, malformed, or too long")]
    InvalidIdentifier,
    #[error("AWS account or catalog id must be a 12 digit identifier")]
    InvalidAccountOrCatalog,
    #[error("AWS region is invalid")]
    InvalidRegion,
    #[error("digest is not a lowercase SHA-256 hex digest")]
    InvalidDigest,
    #[error("scope must contain an allowlisted Glue job")]
    InvalidScope,
    #[error("scope or request fence does not match")]
    ScopeMismatch,
    #[error("revision must be non-zero")]
    InvalidRevision,
    #[error("attempt must be positive")]
    InvalidAttempt,
    #[error("bounds are empty or exceed the Layer-1 safety ceiling")]
    InvalidBounds,
    #[error("timestamp or counter exceeds the Layer-1 safety ceiling")]
    InvalidCounter,
    #[error("capacity summary is invalid")]
    InvalidCapacity,
    #[error("opaque cursor is empty, contains whitespace, or is too large")]
    InvalidCursor,
    #[error("metadata text is invalid")]
    InvalidMetadata,
    #[error("metadata digest does not match its immutable fields")]
    DigestMismatch,
    #[error("registration is invalid")]
    InvalidRegistration,
    #[error("registration or secret reference is already revoked")]
    AlreadyRevoked,
    #[error("registration is not revoked")]
    NotRevoked,
}

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

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

fn valid_identifier(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.trim() == value
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric()
                || matches!(character, '-' | '_' | '.' | ':' | '/' | '@' | '+')
        })
}

fn valid_job_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_JOB_NAME_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_account_or_catalog(value: &str) -> bool {
    value.len() == 12 && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn valid_region(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value == value.to_ascii_lowercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        && !value.starts_with('-')
        && !value.ends_with('-')
}

fn valid_metadata(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && !value.chars().any(char::is_whitespace)
}

macro_rules! string_identifier {
    ($name:ident, $validator:expr) => {
        #[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                if ($validator)(&value) {
                    Ok(Self(value))
                } else {
                    Err(ModelError::InvalidIdentifier)
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

string_identifier!(MissionId, |value: &str| {
    valid_identifier(value, MAX_IDENTIFIER_BYTES)
});
string_identifier!(ProjectId, |value: &str| {
    valid_identifier(value, MAX_IDENTIFIER_BYTES)
});
string_identifier!(WorkProductId, |value: &str| {
    valid_identifier(value, MAX_IDENTIFIER_BYTES)
});
string_identifier!(ServiceId, |value: &str| {
    valid_identifier(value, MAX_IDENTIFIER_BYTES)
});
string_identifier!(ProviderId, |value: &str| {
    valid_identifier(value, MAX_IDENTIFIER_BYTES)
});
string_identifier!(ConsumerId, |value: &str| {
    valid_identifier(value, MAX_IDENTIFIER_BYTES)
});

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AccountId(String);

impl AccountId {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if valid_account_or_catalog(&value) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidAccountOrCatalog)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountId")
            .field("digest", &Digest::from_text(self.as_str()))
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct CatalogId(String);

impl CatalogId {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if valid_account_or_catalog(&value) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidAccountOrCatalog)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for CatalogId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CatalogId")
            .field("digest", &Digest::from_text(self.as_str()))
            .finish()
    }
}

#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AwsRegion(String);

impl AwsRegion {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if valid_region(&value) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidRegion)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AwsRegion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("AwsRegion").field(&self.0).finish()
    }
}

pub type Region = AwsRegion;

string_identifier!(JobName, |value: &str| valid_job_name(value));
string_identifier!(RunId, |value: &str| {
    valid_identifier(value, MAX_RUN_ID_BYTES)
});

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AttemptNumber(u32);

impl AttemptNumber {
    pub fn new(value: u32) -> Result<Self, ModelError> {
        if value == 0 {
            Err(ModelError::InvalidAttempt)
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Timestamp(u64);

impl Timestamp {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn seconds(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsGlueScope {
    account_id: AccountId,
    region: AwsRegion,
    catalog_id: CatalogId,
    allowlisted_jobs: BTreeSet<JobName>,
    mission_id: MissionId,
    project_id: ProjectId,
    work_product_id: WorkProductId,
    work_product_revision: Revision,
    permission_digest: Digest,
    consent_digest: Digest,
    scope_digest: Digest,
}

impl AwsGlueScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: AccountId,
        region: AwsRegion,
        catalog_id: CatalogId,
        allowlisted_jobs: impl IntoIterator<Item = JobName>,
        mission_id: MissionId,
        project_id: ProjectId,
        work_product_id: WorkProductId,
        work_product_revision: Revision,
        permission_digest: Digest,
        consent_digest: Digest,
    ) -> Result<Self, ModelError> {
        let allowlisted_jobs = allowlisted_jobs.into_iter().collect::<BTreeSet<_>>();
        if allowlisted_jobs.is_empty() {
            return Err(ModelError::InvalidScope);
        }
        let scope_digest = Digest::from_fields(
            "aws-glue-scope/v1",
            &[
                account_id.as_str().to_owned(),
                region.as_str().to_owned(),
                catalog_id.as_str().to_owned(),
                allowlisted_jobs
                    .iter()
                    .map(|job| job.as_str().to_owned())
                    .collect::<Vec<_>>()
                    .join(","),
                mission_id.as_str().to_owned(),
                project_id.as_str().to_owned(),
                work_product_id.as_str().to_owned(),
                work_product_revision.get().to_string(),
                permission_digest.as_str().to_owned(),
                consent_digest.as_str().to_owned(),
            ],
        );
        Ok(Self {
            account_id,
            region,
            catalog_id,
            allowlisted_jobs,
            mission_id,
            project_id,
            work_product_id,
            work_product_revision,
            permission_digest,
            consent_digest,
            scope_digest,
        })
    }

    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    pub fn region(&self) -> &AwsRegion {
        &self.region
    }

    pub fn catalog_id(&self) -> &CatalogId {
        &self.catalog_id
    }

    pub fn allowlisted_jobs(&self) -> &BTreeSet<JobName> {
        &self.allowlisted_jobs
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

    pub const fn work_product_revision(&self) -> Revision {
        self.work_product_revision
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

    pub fn contains_job(&self, job: &JobName) -> bool {
        self.allowlisted_jobs.contains(job)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PermissionFence {
    pub account_id: AccountId,
    pub region: AwsRegion,
    pub catalog_id: CatalogId,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub mission_id: MissionId,
    pub project_id: ProjectId,
    pub work_product_id: WorkProductId,
    pub work_product_revision: Revision,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    SigV4,
}

/// An opaque, non-serializing reference into host credential storage.
///
/// The caller-owned reference id is hashed at construction and is never
/// retained. Layer 1 cannot resolve it, sign an HTTP request, or expose it in
/// a receipt.
pub struct SecretReference {
    reference_digest: Digest,
    scope_digest: Digest,
    credential_revision: Revision,
    kind: SecretKind,
    revoked: bool,
}

impl Clone for SecretReference {
    fn clone(&self) -> Self {
        Self {
            reference_digest: self.reference_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            credential_revision: self.credential_revision,
            kind: self.kind,
            revoked: self.revoked,
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
            .field("kind", &self.kind)
            .field("revoked", &self.revoked)
            .finish()
    }
}

impl PartialEq for SecretReference {
    fn eq(&self, other: &Self) -> bool {
        self.reference_digest == other.reference_digest
            && self.scope_digest == other.scope_digest
            && self.credential_revision == other.credential_revision
            && self.kind == other.kind
            && self.revoked == other.revoked
    }
}

impl Eq for SecretReference {}

impl SecretReference {
    pub fn new(
        reference_id: impl Into<String>,
        scope: &AwsGlueScope,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        let reference_id = reference_id.into();
        if !valid_identifier(&reference_id, MAX_IDENTIFIER_BYTES) {
            return Err(ModelError::InvalidIdentifier);
        }
        let credential_revision = Revision::new(credential_revision)?;
        let scope_digest = scope.scope_digest();
        let reference_digest = Digest::from_fields(
            "aws-glue-sigv4-secret-reference/v1",
            &[
                reference_id,
                scope_digest.as_str().to_owned(),
                credential_revision.get().to_string(),
                "sigv4".to_owned(),
            ],
        );
        Ok(Self {
            reference_digest,
            scope_digest,
            credential_revision,
            kind: SecretKind::SigV4,
            revoked: false,
        })
    }

    pub fn sigv4(
        reference_id: impl Into<String>,
        scope: &AwsGlueScope,
        credential_revision: u64,
    ) -> Result<Self, ModelError> {
        Self::new(reference_id, scope, credential_revision)
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

    pub const fn kind(&self) -> SecretKind {
        self.kind
    }

    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            Err(ModelError::AlreadyRevoked)
        } else {
            self.revoked = true;
            Ok(())
        }
    }

    pub fn restore(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            self.revoked = false;
            Ok(())
        } else {
            Err(ModelError::NotRevoked)
        }
    }
}

/// A provider continuation token. Its raw value is retained only inside the
/// opaque transport seam; Debug, Serialize, and evidence expose its digest.
pub struct OpaquePageCursor {
    value: String,
    token_digest: Digest,
    binding_digest: Option<Digest>,
}

impl OpaquePageCursor {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_CURSOR_BYTES
            || value.chars().any(char::is_whitespace)
        {
            return Err(ModelError::InvalidCursor);
        }
        let token_digest =
            Digest::from_fields("aws-glue-page-cursor/v1", std::slice::from_ref(&value));
        Ok(Self {
            value,
            token_digest,
            binding_digest: None,
        })
    }

    #[must_use]
    pub fn bind(&self, binding_digest: &Digest) -> Self {
        Self {
            value: self.value.clone(),
            token_digest: self.token_digest.clone(),
            binding_digest: Some(binding_digest.clone()),
        }
    }

    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }

    pub fn digest(&self) -> Digest {
        self.token_digest.clone()
    }

    pub fn binding_digest(&self) -> Option<&Digest> {
        self.binding_digest.as_ref()
    }
}

impl Clone for OpaquePageCursor {
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
            token_digest: self.token_digest.clone(),
            binding_digest: self.binding_digest.clone(),
        }
    }
}

impl PartialEq for OpaquePageCursor {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value && self.binding_digest == other.binding_digest
    }
}

impl Eq for OpaquePageCursor {}

impl fmt::Debug for OpaquePageCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaquePageCursor")
            .field("token_digest", &self.token_digest)
            .field("binding_digest", &self.binding_digest)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct JobRunReference {
    pub account_id: AccountId,
    pub region: AwsRegion,
    pub catalog_id: CatalogId,
    pub job_name: JobName,
    pub run_id: RunId,
    pub attempt: Option<AttemptNumber>,
}

impl JobRunReference {
    pub fn new(
        account_id: AccountId,
        region: AwsRegion,
        catalog_id: CatalogId,
        job_name: JobName,
        run_id: RunId,
        attempt: Option<AttemptNumber>,
    ) -> Self {
        Self {
            account_id,
            region,
            catalog_id,
            job_name,
            run_id,
            attempt,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum GlueJobRunState {
    Starting,
    Running,
    Stopping,
    Stopped,
    Succeeded,
    Failed,
    Timeout,
    Unknown,
}

impl GlueJobRunState {
    pub fn parse(value: impl AsRef<str>) -> Self {
        match value.as_ref().to_ascii_uppercase().as_str() {
            "STARTING" => Self::Starting,
            "RUNNING" => Self::Running,
            "STOPPING" => Self::Stopping,
            "STOPPED" => Self::Stopped,
            "SUCCEEDED" => Self::Succeeded,
            "FAILED" => Self::Failed,
            "TIMEOUT" => Self::Timeout,
            _ => Self::Unknown,
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Stopped | Self::Succeeded | Self::Failed | Self::Timeout
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CapacitySummary {
    pub max_capacity_milli: Option<u32>,
    pub allocated_capacity_milli: Option<u32>,
    pub dpu_seconds: Option<u64>,
    pub worker_count: Option<u32>,
    pub max_concurrent_runs: Option<u32>,
}

impl CapacitySummary {
    pub fn new(
        max_capacity_milli: Option<u32>,
        allocated_capacity_milli: Option<u32>,
        dpu_seconds: Option<u64>,
        worker_count: Option<u32>,
        max_concurrent_runs: Option<u32>,
    ) -> Result<Self, ModelError> {
        for value in [max_capacity_milli, allocated_capacity_milli] {
            if value.is_some_and(|value| value > MAX_CAPACITY_MILLI) {
                return Err(ModelError::InvalidCapacity);
            }
        }
        for value in [
            dpu_seconds,
            worker_count.map(u64::from),
            max_concurrent_runs.map(u64::from),
        ] {
            if value.is_some_and(|value| value > MAX_COUNTER) {
                return Err(ModelError::InvalidCounter);
            }
        }
        Ok(Self {
            max_capacity_milli,
            allocated_capacity_milli,
            dpu_seconds,
            worker_count,
            max_concurrent_runs,
        })
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        Self::new(
            self.max_capacity_milli,
            self.allocated_capacity_milli,
            self.dpu_seconds,
            self.worker_count,
            self.max_concurrent_runs,
        )
        .map(|_| ())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct JobDefinitionMetadata {
    pub job_name: JobName,
    pub job_arn_digest: Option<Digest>,
    pub created_at: Option<Timestamp>,
    pub updated_at: Option<Timestamp>,
    pub glue_version: Option<String>,
    pub worker_type: Option<String>,
    pub number_of_workers: Option<u32>,
    pub max_capacity_milli: Option<u32>,
    pub timeout_seconds: Option<u32>,
    pub max_concurrent_runs: Option<u32>,
    pub definition_digest: Digest,
}

impl JobDefinitionMetadata {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        job_name: JobName,
        job_arn_digest: Option<Digest>,
        created_at: Option<Timestamp>,
        updated_at: Option<Timestamp>,
        glue_version: Option<String>,
        worker_type: Option<String>,
        number_of_workers: Option<u32>,
        max_capacity_milli: Option<u32>,
        timeout_seconds: Option<u32>,
        max_concurrent_runs: Option<u32>,
    ) -> Result<Self, ModelError> {
        for value in [&glue_version, &worker_type] {
            if value
                .as_deref()
                .is_some_and(|value| !valid_metadata(value, 64))
            {
                return Err(ModelError::InvalidMetadata);
            }
        }
        if number_of_workers.is_some_and(|value| u64::from(value) > MAX_COUNTER)
            || max_concurrent_runs.is_some_and(|value| u64::from(value) > MAX_COUNTER)
        {
            return Err(ModelError::InvalidCounter);
        }
        if max_capacity_milli.is_some_and(|value| value > MAX_CAPACITY_MILLI) {
            return Err(ModelError::InvalidCapacity);
        }
        if timeout_seconds.is_some_and(|value| value > MAX_TIMEOUT_SECONDS) {
            return Err(ModelError::InvalidBounds);
        }
        if let (Some(created), Some(updated)) = (created_at, updated_at)
            && updated.seconds() < created.seconds()
        {
            return Err(ModelError::InvalidCounter);
        }
        let definition_digest = Self::compute_digest(
            &job_name,
            job_arn_digest.as_ref(),
            created_at,
            updated_at,
            glue_version.as_deref(),
            worker_type.as_deref(),
            number_of_workers,
            max_capacity_milli,
            timeout_seconds,
            max_concurrent_runs,
        );
        Ok(Self {
            job_name,
            job_arn_digest,
            created_at,
            updated_at,
            glue_version,
            worker_type,
            number_of_workers,
            max_capacity_milli,
            timeout_seconds,
            max_concurrent_runs,
            definition_digest,
        })
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        let expected = Self::compute_digest(
            &self.job_name,
            self.job_arn_digest.as_ref(),
            self.created_at,
            self.updated_at,
            self.glue_version.as_deref(),
            self.worker_type.as_deref(),
            self.number_of_workers,
            self.max_capacity_milli,
            self.timeout_seconds,
            self.max_concurrent_runs,
        );
        if expected == self.definition_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }

    fn compute_digest(
        job_name: &JobName,
        job_arn_digest: Option<&Digest>,
        created_at: Option<Timestamp>,
        updated_at: Option<Timestamp>,
        glue_version: Option<&str>,
        worker_type: Option<&str>,
        number_of_workers: Option<u32>,
        max_capacity_milli: Option<u32>,
        timeout_seconds: Option<u32>,
        max_concurrent_runs: Option<u32>,
    ) -> Digest {
        Digest::from_fields(
            "aws-glue-job-definition/v1",
            &[
                job_name.as_str().to_owned(),
                job_arn_digest.map_or_else(|| "none".to_owned(), |value| value.as_str().to_owned()),
                created_at.map_or_else(|| "none".to_owned(), |value| value.seconds().to_string()),
                updated_at.map_or_else(|| "none".to_owned(), |value| value.seconds().to_string()),
                glue_version.unwrap_or("none").to_owned(),
                worker_type.unwrap_or("none").to_owned(),
                number_of_workers.map_or_else(|| "none".to_owned(), |value| value.to_string()),
                max_capacity_milli.map_or_else(|| "none".to_owned(), |value| value.to_string()),
                timeout_seconds.map_or_else(|| "none".to_owned(), |value| value.to_string()),
                max_concurrent_runs.map_or_else(|| "none".to_owned(), |value| value.to_string()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct JobRunEvidence {
    pub reference: JobRunReference,
    pub state: GlueJobRunState,
    pub started_at: Option<Timestamp>,
    pub completed_at: Option<Timestamp>,
    pub execution_time_seconds: Option<u64>,
    pub timeout_seconds: Option<u32>,
    pub capacity: CapacitySummary,
    pub arguments_digest: Option<Digest>,
    pub artifact_metadata_digest: Option<Digest>,
    pub diagnostics_digest: Option<Digest>,
    pub run_digest: Digest,
}

impl JobRunEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        reference: JobRunReference,
        state: GlueJobRunState,
        started_at: Option<Timestamp>,
        completed_at: Option<Timestamp>,
        execution_time_seconds: Option<u64>,
        timeout_seconds: Option<u32>,
        capacity: CapacitySummary,
        arguments_digest: Option<Digest>,
        artifact_metadata_digest: Option<Digest>,
        diagnostics_digest: Option<Digest>,
    ) -> Result<Self, ModelError> {
        capacity.validate()?;
        if execution_time_seconds.is_some_and(|value| value > MAX_COUNTER)
            || timeout_seconds.is_some_and(|value| value > MAX_TIMEOUT_SECONDS)
        {
            return Err(ModelError::InvalidCounter);
        }
        if let (Some(started), Some(completed)) = (started_at, completed_at)
            && completed.seconds() < started.seconds()
        {
            return Err(ModelError::InvalidCounter);
        }
        let run_digest = Self::compute_digest(
            &reference,
            state,
            started_at,
            completed_at,
            execution_time_seconds,
            timeout_seconds,
            &capacity,
            arguments_digest.as_ref(),
            artifact_metadata_digest.as_ref(),
            diagnostics_digest.as_ref(),
        );
        Ok(Self {
            reference,
            state,
            started_at,
            completed_at,
            execution_time_seconds,
            timeout_seconds,
            capacity,
            arguments_digest,
            artifact_metadata_digest,
            diagnostics_digest,
            run_digest,
        })
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        self.capacity.validate()?;
        let expected = Self::compute_digest(
            &self.reference,
            self.state,
            self.started_at,
            self.completed_at,
            self.execution_time_seconds,
            self.timeout_seconds,
            &self.capacity,
            self.arguments_digest.as_ref(),
            self.artifact_metadata_digest.as_ref(),
            self.diagnostics_digest.as_ref(),
        );
        if expected == self.run_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }

    pub fn is_timeout(&self) -> bool {
        self.state == GlueJobRunState::Timeout
            || self
                .execution_time_seconds
                .zip(self.timeout_seconds.map(u64::from))
                .is_some_and(|(execution, timeout)| execution >= timeout)
    }

    fn compute_digest(
        reference: &JobRunReference,
        state: GlueJobRunState,
        started_at: Option<Timestamp>,
        completed_at: Option<Timestamp>,
        execution_time_seconds: Option<u64>,
        timeout_seconds: Option<u32>,
        capacity: &CapacitySummary,
        arguments_digest: Option<&Digest>,
        artifact_metadata_digest: Option<&Digest>,
        diagnostics_digest: Option<&Digest>,
    ) -> Digest {
        Digest::from_fields(
            "aws-glue-job-run/v1",
            &[
                reference.account_id.as_str().to_owned(),
                reference.region.as_str().to_owned(),
                reference.catalog_id.as_str().to_owned(),
                reference.job_name.as_str().to_owned(),
                reference.run_id.as_str().to_owned(),
                reference
                    .attempt
                    .map_or_else(|| "none".to_owned(), |value| value.get().to_string()),
                format!("{state:?}"),
                started_at.map_or_else(|| "none".to_owned(), |value| value.seconds().to_string()),
                completed_at.map_or_else(|| "none".to_owned(), |value| value.seconds().to_string()),
                execution_time_seconds.map_or_else(|| "none".to_owned(), |value| value.to_string()),
                timeout_seconds.map_or_else(|| "none".to_owned(), |value| value.to_string()),
                capacity
                    .max_capacity_milli
                    .map_or_else(|| "none".to_owned(), |value| value.to_string()),
                capacity
                    .allocated_capacity_milli
                    .map_or_else(|| "none".to_owned(), |value| value.to_string()),
                capacity
                    .dpu_seconds
                    .map_or_else(|| "none".to_owned(), |value| value.to_string()),
                capacity
                    .worker_count
                    .map_or_else(|| "none".to_owned(), |value| value.to_string()),
                capacity
                    .max_concurrent_runs
                    .map_or_else(|| "none".to_owned(), |value| value.to_string()),
                arguments_digest
                    .map_or_else(|| "none".to_owned(), |value| value.as_str().to_owned()),
                artifact_metadata_digest
                    .map_or_else(|| "none".to_owned(), |value| value.as_str().to_owned()),
                diagnostics_digest
                    .map_or_else(|| "none".to_owned(), |value| value.as_str().to_owned()),
            ],
        )
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
    Truncated,
    Tampered,
    CursorBinding,
    ScopeMismatch,
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
    pub status_code: Option<u16>,
    pub retryable: bool,
    pub provider_attempt: u8,
    pub error_digest: Digest,
}

impl ProviderErrorEvidence {
    pub(crate) fn new(
        kind: ProviderErrorKind,
        status_code: Option<u16>,
        retryable: bool,
        provider_attempt: u8,
        diagnostic_digest: &Digest,
    ) -> Self {
        let error_digest = Digest::from_fields(
            "aws-glue-provider-error/v1",
            &[
                format!("{kind:?}"),
                status_code.map_or_else(|| "none".to_owned(), |value| value.to_string()),
                retryable.to_string(),
                provider_attempt.to_string(),
                diagnostic_digest.as_str().to_owned(),
            ],
        );
        Self {
            kind,
            status_code,
            retryable,
            provider_attempt,
            error_digest,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ResultBounds {
    max_runs: u32,
    page_size: u32,
    max_pages: u8,
    timeout_seconds: u32,
}

impl ResultBounds {
    pub fn new(
        max_runs: u32,
        page_size: u32,
        max_pages: u8,
        timeout_seconds: u32,
    ) -> Result<Self, ModelError> {
        if max_runs == 0
            || max_runs > MAX_RUNS
            || page_size == 0
            || page_size > MAX_PAGE_SIZE
            || max_pages == 0
            || max_pages > MAX_PAGES
            || timeout_seconds == 0
            || timeout_seconds > MAX_TIMEOUT_SECONDS
        {
            return Err(ModelError::InvalidBounds);
        }
        Ok(Self {
            max_runs,
            page_size,
            max_pages,
            timeout_seconds,
        })
    }

    pub const fn max_runs(self) -> u32 {
        self.max_runs
    }

    pub const fn page_size(self) -> u32 {
        self.page_size
    }

    pub const fn max_pages(self) -> u8 {
        self.max_pages
    }

    pub const fn timeout_seconds(self) -> u32 {
        self.timeout_seconds
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobRunRead {
    GetJobRun {
        run_id: RunId,
        expected_attempt: Option<AttemptNumber>,
    },
    GetJobRuns {
        expected_attempt: Option<AttemptNumber>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AwsGlueJobResultRequest {
    pub job_name: JobName,
    pub read: JobRunRead,
    pub bounds: ResultBounds,
    pub include_job_definition: bool,
    pub work_product_revision: Revision,
    pub request_digest: Digest,
}

impl AwsGlueJobResultRequest {
    pub fn get_job_run(
        job_name: JobName,
        run_id: RunId,
        expected_attempt: Option<AttemptNumber>,
        bounds: ResultBounds,
        include_job_definition: bool,
        work_product_revision: Revision,
    ) -> Self {
        Self::new(
            job_name,
            JobRunRead::GetJobRun {
                run_id,
                expected_attempt,
            },
            bounds,
            include_job_definition,
            work_product_revision,
        )
    }

    pub fn get_job_runs(
        job_name: JobName,
        expected_attempt: Option<AttemptNumber>,
        bounds: ResultBounds,
        include_job_definition: bool,
        work_product_revision: Revision,
    ) -> Self {
        Self::new(
            job_name,
            JobRunRead::GetJobRuns { expected_attempt },
            bounds,
            include_job_definition,
            work_product_revision,
        )
    }

    pub fn new(
        job_name: JobName,
        read: JobRunRead,
        bounds: ResultBounds,
        include_job_definition: bool,
        work_product_revision: Revision,
    ) -> Self {
        let mut request = Self {
            job_name,
            read,
            bounds,
            include_job_definition,
            work_product_revision,
            request_digest: Digest::from_text("uninitialized-request"),
        };
        request.request_digest = request.recomputed_digest();
        request
    }

    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_fields(
            "aws-glue-job-result-request/v1",
            &[
                self.job_name.as_str().to_owned(),
                format!("{:?}", self.read),
                self.bounds.max_runs().to_string(),
                self.bounds.page_size().to_string(),
                self.bounds.max_pages().to_string(),
                self.bounds.timeout_seconds().to_string(),
                self.include_job_definition.to_string(),
                self.work_product_revision.get().to_string(),
            ],
        )
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        if self.request_digest == self.recomputed_digest() {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }

    pub const fn operation(&self) -> ReadOperation {
        match &self.read {
            JobRunRead::GetJobRun { .. } => ReadOperation::GetJobRun,
            JobRunRead::GetJobRuns { .. } => ReadOperation::GetJobRuns,
        }
    }

    pub fn run_id(&self) -> Option<&RunId> {
        match &self.read {
            JobRunRead::GetJobRun { run_id, .. } => Some(run_id),
            JobRunRead::GetJobRuns { .. } => None,
        }
    }

    pub fn expected_attempt(&self) -> Option<AttemptNumber> {
        match self.read {
            JobRunRead::GetJobRun {
                expected_attempt, ..
            }
            | JobRunRead::GetJobRuns { expected_attempt } => expected_attempt,
        }
    }
}

pub type JobResultRequest = AwsGlueJobResultRequest;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadOperation {
    GetJobRun,
    GetJobRuns,
    GetJobDefinition,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultStatus {
    Starting,
    Running,
    Stopping,
    Stopped,
    Succeeded,
    Failed,
    Timeout,
    Partial,
    AccessLost,
    ProviderUnknown,
    FinalError,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialReason {
    RunCap,
    PageCap,
    Timeout,
    MissingCursor,
    Truncated,
    DefinitionUnavailable,
    OrderingUnproven,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultProjection {
    Starting,
    Running,
    Stopping,
    Stopped,
    Succeeded,
    Failed,
    Timeout,
    Partial(PartialReason),
    AccessLost,
    ProviderUnknown,
    FinalError,
}

impl ResultProjection {
    pub const fn status(self) -> ResultStatus {
        match self {
            Self::Starting => ResultStatus::Starting,
            Self::Running => ResultStatus::Running,
            Self::Stopping => ResultStatus::Stopping,
            Self::Stopped => ResultStatus::Stopped,
            Self::Succeeded => ResultStatus::Succeeded,
            Self::Failed => ResultStatus::Failed,
            Self::Timeout => ResultStatus::Timeout,
            Self::Partial(_) => ResultStatus::Partial,
            Self::AccessLost => ResultStatus::AccessLost,
            Self::ProviderUnknown => ResultStatus::ProviderUnknown,
            Self::FinalError => ResultStatus::FinalError,
        }
    }

    pub const fn is_adoptable_layer_one(self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RetryProjection {
    pub provider_attempts: u8,
    pub provider_retry_count: u8,
    pub job_attempts: Vec<AttemptNumber>,
    pub retried: bool,
    pub retry_digest: Digest,
}

impl RetryProjection {
    pub(crate) fn new(
        provider_attempts: u8,
        provider_retry_count: u8,
        job_attempts: Vec<AttemptNumber>,
    ) -> Self {
        let retried = provider_retry_count > 0 || job_attempts.len() > 1;
        let retry_digest =
            Self::compute_digest(provider_attempts, provider_retry_count, &job_attempts);
        Self {
            provider_attempts,
            provider_retry_count,
            job_attempts,
            retried,
            retry_digest,
        }
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        let expected = Self::compute_digest(
            self.provider_attempts,
            self.provider_retry_count,
            &self.job_attempts,
        );
        if expected == self.retry_digest {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }

    fn compute_digest(
        provider_attempts: u8,
        provider_retry_count: u8,
        job_attempts: &[AttemptNumber],
    ) -> Digest {
        Digest::from_fields(
            "aws-glue-retry-projection/v1",
            &[
                provider_attempts.to_string(),
                provider_retry_count.to_string(),
                job_attempts
                    .iter()
                    .map(|attempt| attempt.get().to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeoutProjection {
    NotObserved,
    RunTimeout,
    ProviderTimeout,
    Bounded { timeout_seconds: u32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Fixture,
    Recording,
    Fake,
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

    pub const fn is_blocked_env(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdoptionAvailability {
    NotAdoptedLayer2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AwsGlueRegistration {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: ServiceId,
    pub provider_id: ProviderId,
    pub consumer_id: ConsumerId,
    pub provider_version: String,
    pub api_digest: Digest,
    pub provider_digest: Digest,
    pub contract_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_digest: Digest,
    pub revision: Revision,
    pub state: RegistrationState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RegistrationTransition {
    pub registration_digest: Digest,
    pub prior_state: RegistrationState,
    pub next_state: RegistrationState,
    pub revision: Revision,
    pub transition_digest: Digest,
}

impl AwsGlueRegistration {
    pub fn new(
        scope: &AwsGlueScope,
        secret_reference: &SecretReference,
        provider_id: ProviderId,
        provider_version: impl Into<String>,
        api_digest: Digest,
        provider_digest: Digest,
    ) -> Result<Self, ModelError> {
        let provider_version = provider_version.into();
        if provider_version.is_empty()
            || provider_id.as_str() != crate::AWS_GLUE_JOB_RESULT_PROVIDER_ID
            || secret_reference.scope_digest() != &scope.scope_digest()
            || secret_reference.is_revoked()
        {
            return Err(ModelError::InvalidRegistration);
        }
        let service_id = ServiceId::new(AWS_GLUE_JOB_RESULT_SERVICE_ID)
            .map_err(|_| ModelError::InvalidRegistration)?;
        let consumer_id = ConsumerId::new(AWS_GLUE_JOB_RESULT_CONSUMER_ID)
            .map_err(|_| ModelError::InvalidRegistration)?;
        let revision = Revision::new(1)?;
        let contract_digest = crate::contract_digest();
        let mut registration = Self {
            schema_version: AWS_GLUE_JOB_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: AWS_GLUE_JOB_RESULT_CONTRACT_VERSION.to_owned(),
            service_id,
            provider_id,
            consumer_id,
            provider_version,
            api_digest,
            provider_digest,
            contract_digest,
            permission_digest: scope.permission_digest().clone(),
            scope_digest: scope.scope_digest(),
            secret_reference_digest: secret_reference.reference_digest().clone(),
            registration_digest: Digest::from_text("uninitialized-registration"),
            revision,
            state: RegistrationState::Active,
        };
        registration.registration_digest = registration.recomputed_digest();
        Ok(registration)
    }

    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_fields(
            "aws-glue-registration/v1",
            &[
                self.schema_version.clone(),
                self.contract_version.clone(),
                self.service_id.as_str().to_owned(),
                self.provider_id.as_str().to_owned(),
                self.consumer_id.as_str().to_owned(),
                self.provider_version.clone(),
                self.api_digest.as_str().to_owned(),
                self.provider_digest.as_str().to_owned(),
                self.contract_digest.as_str().to_owned(),
                self.permission_digest.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.secret_reference_digest.as_str().to_owned(),
                self.revision.get().to_string(),
                format!("{:?}", self.state),
            ],
        )
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        if self.registration_digest == self.recomputed_digest() {
            Ok(())
        } else {
            Err(ModelError::DigestMismatch)
        }
    }

    pub fn ensure_active(&self) -> Result<(), ModelError> {
        self.validate_digest()?;
        if self.state == RegistrationState::Active {
            Ok(())
        } else {
            Err(ModelError::AlreadyRevoked)
        }
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransition, ModelError> {
        self.ensure_active()?;
        let prior_state = self.state;
        self.state = RegistrationState::Revoked;
        self.revision = Revision::new(self.revision.get().saturating_add(1))?;
        self.registration_digest = self.recomputed_digest();
        Ok(RegistrationTransition {
            registration_digest: self.registration_digest.clone(),
            prior_state,
            next_state: self.state,
            revision: self.revision,
            transition_digest: Digest::from_fields(
                "aws-glue-registration-transition/v1",
                &[
                    self.registration_digest.as_str().to_owned(),
                    format!("{prior_state:?}"),
                    format!("{:?}", self.state),
                    self.revision.get().to_string(),
                ],
            ),
        })
    }

    pub fn restore(&mut self) -> Result<RegistrationTransition, ModelError> {
        if self.state != RegistrationState::Revoked {
            return Err(ModelError::NotRevoked);
        }
        let prior_state = self.state;
        self.state = RegistrationState::Active;
        self.revision = Revision::new(self.revision.get().saturating_add(1))?;
        self.registration_digest = self.recomputed_digest();
        Ok(RegistrationTransition {
            registration_digest: self.registration_digest.clone(),
            prior_state,
            next_state: self.state,
            revision: self.revision,
            transition_digest: Digest::from_fields(
                "aws-glue-registration-transition/v1",
                &[
                    self.registration_digest.as_str().to_owned(),
                    format!("{prior_state:?}"),
                    format!("{:?}", self.state),
                    self.revision.get().to_string(),
                ],
            ),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EvidenceDigests {
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub job_digest: Digest,
    pub run_digest: Digest,
    pub evidence_digest: Digest,
}
