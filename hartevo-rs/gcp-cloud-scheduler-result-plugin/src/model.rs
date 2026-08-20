//! Bounded, typed, and redacted models for Google Cloud Scheduler reads.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{
    GCP_CLOUD_SCHEDULER_CONTRACT_VERSION, GCP_CLOUD_SCHEDULER_PLUGIN_VERSION_TEXT,
    GCP_CLOUD_SCHEDULER_PROVIDER_ID, GCP_CLOUD_SCHEDULER_PROVIDER_VERSION_TEXT,
    GCP_CLOUD_SCHEDULER_SCHEMA_VERSION,
};

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_SCHEDULE_BYTES: usize = 512;
pub const MAX_OPAQUE_PAGE_TOKEN_BYTES: usize = 4_096;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_DIGEST_INPUT_BYTES: usize = 32_768;
pub const MAX_PAGES: u16 = 16;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_JOBS: usize = 500;
pub const MAX_DIAGNOSTIC_BYTES: usize = 512;

/// A lowercase SHA-256 digest used at every cross-boundary seam.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    #[must_use]
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Self {
        Self(hex::encode(Sha256::digest(bytes.as_ref())))
    }

    #[must_use]
    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value)
    }

    #[must_use]
    pub fn from_serializable<T: Serialize>(value: &T) -> Self {
        let bytes = serde_json::to_vec(value).expect("bounded Scheduler value serializes");
        Self::from_bytes(bytes)
    }

    pub fn parse(value: impl Into<String>, field: &'static str) -> Result<Self, ModelError> {
        let value = value.into();
        if is_digest(&value) {
            Ok(Self(value))
        } else {
            Err(ModelError::InvalidDigest { field })
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        64
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
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

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    #[error("{field} is empty")]
    Empty { field: &'static str },
    #[error("{field} is too long")]
    TooLong { field: &'static str },
    #[error("{field} contains control characters or surrounding whitespace")]
    InvalidText { field: &'static str },
    #[error("{field} is not a valid identifier")]
    InvalidIdentifier { field: &'static str },
    #[error("{field} is not a lowercase SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} must be positive")]
    MustBePositive { field: &'static str },
    #[error("{field} is outside the Layer-1 bound")]
    OutsideBound { field: &'static str },
    #[error("permission scope is not exactly the read-only Cloud Scheduler list/get scope")]
    InvalidPermission,
    #[error("consent scope is not read-only")]
    InvalidConsent,
    #[error("Cloud Scheduler scope is invalid")]
    InvalidScope,
    #[error("Cloud Scheduler schedule is invalid")]
    InvalidSchedule,
    #[error("Cloud Scheduler target is invalid")]
    InvalidTarget,
    #[error("provider payload is malformed or outside the allowlist")]
    InvalidProviderPayload,
    #[error("provider payload drifted from the bound project, location, job, schedule, or target")]
    ScopeDrift,
    #[error("registration is already revoked")]
    AlreadyRevoked,
    #[error("registration or secret reference is not revoked")]
    NotRevoked,
    #[error("revision overflowed")]
    RevisionOverflow,
}

fn validate_text(
    value: &str,
    field: &'static str,
    maximum: usize,
    allow_internal_whitespace: bool,
) -> Result<(), ModelError> {
    if value.is_empty() {
        return Err(ModelError::Empty { field });
    }
    if value.len() > maximum {
        return Err(ModelError::TooLong { field });
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(ModelError::InvalidText { field });
    }
    if !allow_internal_whitespace && value.chars().any(char::is_whitespace) {
        return Err(ModelError::InvalidIdentifier { field });
    }
    Ok(())
}

fn validate_identifier(value: &str, field: &'static str) -> Result<(), ModelError> {
    validate_text(value, field, MAX_IDENTIFIER_BYTES, false)?;
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'@' | b'=')
    }) {
        return Err(ModelError::InvalidIdentifier { field });
    }
    Ok(())
}

macro_rules! bounded_identifier {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                validate_identifier(&value, $field)?;
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            #[must_use]
            pub fn digest(&self) -> Digest {
                Digest::from_text(self.as_str())
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
    };
}

bounded_identifier!(ProjectId, "Google Cloud project id");
bounded_identifier!(Location, "Google Cloud location");
bounded_identifier!(JobId, "Cloud Scheduler job id");
bounded_identifier!(MissionId, "Mission id");
bounded_identifier!(WorkProductId, "Work Product id");

pub type GcpProjectId = ProjectId;
pub type GcpJobId = JobId;

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

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    pub fn next(self) -> Result<Self, ModelError> {
        Self::new(self.0.checked_add(1).ok_or(ModelError::RevisionOverflow)?)
    }
}

impl fmt::Display for Revision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectBinding {
    project_id: String,
    revision: Revision,
}

impl ProjectBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        let project_id = id.into();
        validate_identifier(&project_id, "Hartevo project id")?;
        Ok(Self {
            project_id,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn project_id(&self) -> &str {
        &self.project_id
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionBinding {
    mission_id: MissionId,
    revision: Revision,
}

impl MissionBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            mission_id: MissionId::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkProductBinding {
    work_product_id: WorkProductId,
    revision: Revision,
}

impl WorkProductBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            work_product_id: WorkProductId::new(id)?,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn work_product_id(&self) -> &WorkProductId {
        &self.work_product_id
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

pub type Project = ProjectBinding;
pub type Mission = MissionBinding;
pub type WorkProduct = WorkProductBinding;

#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ScheduleExpression(String);

impl ScheduleExpression {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        validate_text(&value, "Cloud Scheduler schedule", MAX_SCHEDULE_BYTES, true)
            .map_err(|_| ModelError::InvalidSchedule)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_text(self.as_str())
    }
}

impl fmt::Debug for ScheduleExpression {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ScheduleExpression")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for ScheduleExpression {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum JobSelector {
    Any,
    Exact { job_id: JobId },
}

impl JobSelector {
    #[must_use]
    pub const fn any() -> Self {
        Self::Any
    }

    #[must_use]
    pub fn exact(id: impl Into<String>) -> Self {
        Self::Exact {
            job_id: JobId::new(id).expect("JobSelector::exact receives a valid job id"),
        }
    }

    pub fn try_exact(id: impl Into<String>) -> Result<Self, ModelError> {
        Ok(Self::Exact {
            job_id: JobId::new(id)?,
        })
    }

    #[must_use]
    pub fn job_id(&self) -> Option<&JobId> {
        match self {
            Self::Any => None,
            Self::Exact { job_id } => Some(job_id),
        }
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }

    #[must_use]
    pub fn matches(&self, id: &JobId) -> bool {
        self.job_id().is_none_or(|expected| expected == id)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum ScheduleSelector {
    Any,
    Exact { expression: ScheduleExpression },
}

impl ScheduleSelector {
    #[must_use]
    pub const fn any() -> Self {
        Self::Any
    }

    #[must_use]
    pub fn exact(expression: impl Into<String>) -> Self {
        Self::Exact {
            expression: ScheduleExpression::new(expression)
                .expect("ScheduleSelector::exact receives a valid schedule"),
        }
    }

    pub fn try_exact(expression: impl Into<String>) -> Result<Self, ModelError> {
        Ok(Self::Exact {
            expression: ScheduleExpression::new(expression)?,
        })
    }

    #[must_use]
    pub fn expression(&self) -> Option<&ScheduleExpression> {
        match self {
            Self::Any => None,
            Self::Exact { expression } => Some(expression),
        }
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }

    #[must_use]
    pub fn matches(&self, expression: &ScheduleExpression) -> bool {
        self.expression()
            .is_none_or(|expected| expected == expression)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    Http,
    PubSub,
    AppEngine,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum TargetSelector {
    Any,
    Exact {
        kind: Option<TargetKind>,
        target_digest: Digest,
    },
}

impl TargetSelector {
    #[must_use]
    pub const fn any() -> Self {
        Self::Any
    }

    #[must_use]
    pub fn exact(target: impl AsRef<[u8]>) -> Self {
        Self::Exact {
            kind: None,
            target_digest: Digest::from_bytes(target),
        }
    }

    #[must_use]
    pub fn exact_kind(kind: TargetKind, target: impl AsRef<[u8]>) -> Self {
        Self::Exact {
            kind: Some(kind),
            target_digest: Digest::from_bytes(target),
        }
    }

    pub fn exact_digest(
        kind: Option<TargetKind>,
        target_digest: Digest,
    ) -> Result<Self, ModelError> {
        Digest::parse(target_digest.as_str().to_owned(), "target digest")?;
        Ok(Self::Exact {
            kind,
            target_digest,
        })
    }

    #[must_use]
    pub fn kind(&self) -> Option<TargetKind> {
        match self {
            Self::Any => None,
            Self::Exact { kind, .. } => *kind,
        }
    }

    #[must_use]
    pub fn target_digest(&self) -> Option<&Digest> {
        match self {
            Self::Any => None,
            Self::Exact { target_digest, .. } => Some(target_digest),
        }
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }

    #[must_use]
    pub fn matches(&self, target: &TargetSummary) -> bool {
        match self {
            Self::Any => true,
            Self::Exact {
                kind,
                target_digest,
            } => {
                (target_digest == &target.target_digest
                    || target
                        .endpoint_digest
                        .as_ref()
                        .is_some_and(|endpoint| target_digest == endpoint))
                    && kind.is_none_or(|value| value == target.kind)
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TargetSummary {
    pub kind: TargetKind,
    pub target_digest: Digest,
    pub endpoint_digest: Option<Digest>,
    pub payload_digest: Option<Digest>,
}

impl TargetSummary {
    pub fn new(
        kind: TargetKind,
        target_digest: Digest,
        endpoint_digest: Option<Digest>,
        payload_digest: Option<Digest>,
    ) -> Result<Self, ModelError> {
        Digest::parse(target_digest.as_str().to_owned(), "target digest")?;
        if let Some(digest) = &endpoint_digest {
            Digest::parse(digest.as_str().to_owned(), "endpoint digest")?;
        }
        if let Some(digest) = &payload_digest {
            Digest::parse(digest.as_str().to_owned(), "payload digest")?;
        }
        Ok(Self {
            kind,
            target_digest,
            endpoint_digest,
            payload_digest,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SchedulerJobState {
    Enabled,
    Paused,
    Disabled,
    #[serde(other)]
    Unknown,
}

impl SchedulerJobState {
    #[must_use]
    pub fn parse(value: Option<&str>) -> Self {
        match value.unwrap_or_default().to_ascii_uppercase().as_str() {
            "ENABLED" => Self::Enabled,
            "PAUSED" => Self::Paused,
            "DISABLED" => Self::Disabled,
            _ => Self::Unknown,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => "ENABLED",
            Self::Paused => "PAUSED",
            Self::Disabled => "DISABLED",
            Self::Unknown => "UNKNOWN",
        }
    }
}

pub type CloudSchedulerJobState = SchedulerJobState;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SchedulerJobSummary {
    pub job_id: JobId,
    pub project_id: ProjectId,
    pub location: Location,
    pub schedule: ScheduleExpression,
    pub target: TargetSummary,
    pub state: SchedulerJobState,
    pub last_attempt_status: Option<i32>,
    pub status_digest: Option<Digest>,
    pub resource_revision: Revision,
    pub job_digest: Digest,
}

impl SchedulerJobSummary {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        job_id: JobId,
        project_id: ProjectId,
        location: Location,
        schedule: ScheduleExpression,
        target: TargetSummary,
        state: SchedulerJobState,
        last_attempt_status: Option<i32>,
        status_digest: Option<Digest>,
        resource_revision: Revision,
    ) -> Result<Self, ModelError> {
        if let Some(digest) = &status_digest {
            Digest::parse(digest.as_str().to_owned(), "status digest")?;
        }
        let mut job = Self {
            job_id,
            project_id,
            location,
            schedule,
            target,
            state,
            last_attempt_status,
            status_digest,
            resource_revision,
            job_digest: Digest::from_text("placeholder"),
        };
        job.job_digest = job.compute_digest();
        Ok(job)
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&(
            &self.job_id,
            &self.project_id,
            &self.location,
            &self.schedule,
            &self.target,
            self.state,
            self.last_attempt_status,
            &self.status_digest,
            self.resource_revision,
        ))
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        self.job_digest.clone()
    }

    #[must_use]
    pub fn verify_digest(&self) -> bool {
        self.job_digest == self.compute_digest()
    }

    #[must_use]
    pub fn matches_scope(&self, scope: &GcpCloudSchedulerScope) -> bool {
        self.project_id == scope.gcp_project
            && self.location == scope.location
            && scope.job.matches(&self.job_id)
            && scope.schedule.matches(&self.schedule)
            && scope.target.matches(&self.target)
    }
}

pub type CloudSchedulerJob = SchedulerJobSummary;
pub type GcpCloudSchedulerJob = SchedulerJobSummary;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionAction {
    JobsList,
    JobsGet,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionScope {
    actions: BTreeSet<PermissionAction>,
    digest: Digest,
}

impl PermissionScope {
    pub fn new(actions: BTreeSet<PermissionAction>) -> Result<Self, ModelError> {
        if actions.len() != 2
            || !actions.contains(&PermissionAction::JobsList)
            || !actions.contains(&PermissionAction::JobsGet)
        {
            return Err(ModelError::InvalidPermission);
        }
        let digest = Digest::from_serializable(&actions);
        Ok(Self { actions, digest })
    }

    #[must_use]
    pub fn read_only() -> Self {
        Self::new(BTreeSet::from([
            PermissionAction::JobsGet,
            PermissionAction::JobsList,
        ]))
        .expect("the built-in Cloud Scheduler read scope is valid")
    }

    #[must_use]
    pub fn actions(&self) -> &BTreeSet<PermissionAction> {
        &self.actions
    }

    #[must_use]
    pub fn allows(&self, action: PermissionAction) -> bool {
        self.actions.contains(&action)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        Self::new(self.actions.clone()).map(|_| ())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        self.digest.clone()
    }
}

pub type GcpCloudSchedulerPermission = PermissionScope;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentScope {
    reference_digest: Digest,
    revision: Revision,
    read_only: bool,
    digest: Digest,
}

impl ConsentScope {
    pub fn new(reference: impl AsRef<[u8]>, revision: u64) -> Result<Self, ModelError> {
        let reference = reference.as_ref();
        if reference.is_empty() || reference.len() > MAX_IDENTIFIER_BYTES {
            return Err(ModelError::InvalidConsent);
        }
        let revision = Revision::new(revision)?;
        let reference_digest = Digest::from_bytes(reference);
        let digest = Digest::from_serializable(&(&reference_digest, revision, true));
        Ok(Self {
            reference_digest,
            revision,
            read_only: true,
            digest,
        })
    }

    #[must_use]
    pub fn read_only() -> Self {
        Self::new("gcp-cloud-scheduler-read-only", 1)
            .expect("the built-in Cloud Scheduler consent is valid")
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if !self.read_only
            || !is_digest(self.reference_digest.as_str())
            || !is_digest(self.digest.as_str())
        {
            Err(ModelError::InvalidConsent)
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub const fn is_read_only(&self) -> bool {
        self.read_only
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        self.digest.clone()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretReferenceKind {
    OAuth,
    ServiceAccount,
}

/// An opaque host-keyring reference. The supplied handle is hashed at the
/// boundary and is never retained, serialized, or included in Debug output.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretReferenceKind,
    reference_digest: Digest,
    scope_digest: Digest,
    revision: Revision,
    revoked: bool,
}

impl SecretReference {
    pub fn new(
        opaque_reference: impl AsRef<str>,
        scope: &GcpCloudSchedulerScope,
        revision: u64,
        kind: SecretReferenceKind,
    ) -> Result<Self, ModelError> {
        Self::for_scope(kind, opaque_reference, scope, Revision::new(revision)?)
    }

    pub fn oauth(
        opaque_reference: impl AsRef<str>,
        scope: &GcpCloudSchedulerScope,
        revision: u64,
    ) -> Result<Self, ModelError> {
        Self::new(
            opaque_reference,
            scope,
            revision,
            SecretReferenceKind::OAuth,
        )
    }

    pub fn service_account(
        opaque_reference: impl AsRef<str>,
        scope: &GcpCloudSchedulerScope,
        revision: u64,
    ) -> Result<Self, ModelError> {
        Self::new(
            opaque_reference,
            scope,
            revision,
            SecretReferenceKind::ServiceAccount,
        )
    }

    pub fn unbound(
        opaque_reference: impl AsRef<str>,
        revision: u64,
        kind: SecretReferenceKind,
    ) -> Result<Self, ModelError> {
        let revision = Revision::new(revision)?;
        validate_text(
            opaque_reference.as_ref(),
            "opaque OAuth or service-account SecretReference",
            MAX_IDENTIFIER_BYTES,
            true,
        )?;
        let scope_digest = Digest::from_text("unbound-cloud-scheduler-secret");
        let reference_digest = Digest::from_serializable(&(
            "hartevo:gcp-cloud-scheduler-secret-reference:v1",
            kind,
            opaque_reference.as_ref(),
            &scope_digest,
            revision,
        ));
        Ok(Self {
            kind,
            reference_digest,
            scope_digest,
            revision,
            revoked: false,
        })
    }

    fn for_scope(
        kind: SecretReferenceKind,
        opaque_reference: impl AsRef<str>,
        scope: &GcpCloudSchedulerScope,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        let opaque_reference = opaque_reference.as_ref();
        validate_text(
            opaque_reference,
            "opaque OAuth or service-account SecretReference",
            MAX_IDENTIFIER_BYTES,
            true,
        )?;
        let scope_digest = scope.scope_digest();
        let reference_digest = Digest::from_serializable(&(
            "hartevo:gcp-cloud-scheduler-secret-reference:v1",
            kind,
            opaque_reference,
            &scope_digest,
            revision,
        ));
        Ok(Self {
            kind,
            reference_digest,
            scope_digest,
            revision,
            revoked: false,
        })
    }

    #[must_use]
    pub const fn kind(&self) -> SecretReferenceKind {
        self.kind
    }

    #[must_use]
    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        self.reference_digest.clone()
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
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

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("kind", &self.kind)
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("revision", &self.revision)
            .field("revoked", &self.revoked)
            .finish()
    }
}

pub type OAuthSecretReference = SecretReference;
pub type ServiceAccountSecretReference = SecretReference;
pub type GcpAuthKind = SecretReferenceKind;
pub type GoogleAuthKind = SecretReferenceKind;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpCloudSchedulerScope {
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub gcp_project: ProjectId,
    pub location: Location,
    pub job: JobSelector,
    pub schedule: ScheduleSelector,
    pub target: TargetSelector,
    pub permission: PermissionScope,
    pub consent: ConsentScope,
}

impl GcpCloudSchedulerScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
        gcp_project: impl Into<String>,
        location: impl Into<String>,
        job: JobSelector,
        schedule: ScheduleSelector,
        target: TargetSelector,
        permission: PermissionScope,
        consent: ConsentScope,
    ) -> Result<Self, ModelError> {
        let scope = Self {
            project,
            mission,
            work_product,
            gcp_project: ProjectId::new(gcp_project)?,
            location: Location::new(location)?,
            job,
            schedule,
            target,
            permission,
            consent,
        };
        scope.validate()?;
        Ok(scope)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn read_only(
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
        gcp_project: impl Into<String>,
        location: impl Into<String>,
        job: JobSelector,
        schedule: ScheduleSelector,
        target: TargetSelector,
        consent: ConsentScope,
    ) -> Result<Self, ModelError> {
        Self::new(
            project,
            mission,
            work_product,
            gcp_project,
            location,
            job,
            schedule,
            target,
            PermissionScope::read_only(),
            consent,
        )
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.permission.validate()?;
        self.consent.validate()?;
        if self.project.revision().get() == 0
            || self.mission.revision().get() == 0
            || self.work_product.revision().get() == 0
        {
            return Err(ModelError::InvalidScope);
        }
        Ok(())
    }

    #[must_use]
    pub fn scope_digest(&self) -> Digest {
        Digest::from_serializable(self)
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        self.scope_digest()
    }

    #[must_use]
    pub fn permission_digest(&self) -> Digest {
        self.permission.digest()
    }

    #[must_use]
    pub fn consent_digest(&self) -> Digest {
        self.consent.digest()
    }

    #[must_use]
    pub fn schedule_digest(&self) -> Digest {
        self.schedule.digest()
    }

    #[must_use]
    pub fn target_digest(&self) -> Digest {
        self.target.digest()
    }

    #[must_use]
    pub fn mission_revision(&self) -> Revision {
        self.mission.revision()
    }

    #[must_use]
    pub fn project_revision(&self) -> Revision {
        self.project.revision()
    }

    #[must_use]
    pub fn work_product_revision(&self) -> Revision {
        self.work_product.revision()
    }

    #[must_use]
    pub fn project_id(&self) -> &ProjectId {
        &self.gcp_project
    }

    #[must_use]
    pub fn job_id(&self) -> Option<&JobId> {
        self.job.job_id()
    }
}

pub type GcpCloudSchedulerResultScope = GcpCloudSchedulerScope;
pub type CloudSchedulerScope = GcpCloudSchedulerScope;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    Complete,
    Partial,
    Stale,
    AccessLost,
    NotFound,
    Conflict,
    RateLimited,
    Timeout,
    ProviderUnknown,
}

impl EvidenceState {
    #[must_use]
    pub const fn is_provider_failure(self) -> bool {
        !matches!(self, Self::Complete | Self::Partial | Self::Stale)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudSchedulerOperation {
    List,
    Get,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl TransportProvenance {
    #[must_use]
    pub const fn is_native(self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_connected(self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_first_party(self) -> bool {
        false
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::Recording => "recording",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "BLOCKED_ENV",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudSchedulerResponseReceipt {
    pub status_code: u16,
    pub body_digest: Digest,
    pub body_bytes: usize,
    pub provenance: TransportProvenance,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudSchedulerRequestReceipt {
    pub operation: CloudSchedulerOperation,
    pub method: String,
    pub path: String,
    pub project_digest: Digest,
    pub location_digest: Digest,
    pub job_digest: Option<Digest>,
    pub schedule_digest: Digest,
    pub target_digest: Digest,
    pub page_token_digest: Option<Digest>,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub request_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceDigests {
    pub version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub secret_reference_digest: Digest,
    pub evidence_digest: Digest,
}

impl EvidenceDigests {
    #[must_use]
    pub fn new(
        provider_digest: Digest,
        permission_digest: Digest,
        scope_digest: Digest,
        secret_reference_digest: Digest,
    ) -> Self {
        Self {
            version_digest: Digest::from_text(GCP_CLOUD_SCHEDULER_PLUGIN_VERSION_TEXT),
            contract_digest: crate::contract_digest(),
            provider_digest,
            permission_digest,
            scope_digest,
            secret_reference_digest,
            evidence_digest: Digest::from_text("placeholder"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpCloudSchedulerEvidence {
    pub schema_version: String,
    pub contract_version: String,
    pub plugin_version: String,
    pub operation: CloudSchedulerOperation,
    pub state: EvidenceState,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub provider_revision: String,
    pub project_revision: Revision,
    pub mission_revision: Revision,
    pub work_product_revision: Revision,
    pub page_count: u16,
    pub job_count: u16,
    pub duplicate_job_count: u16,
    pub jobs: Vec<SchedulerJobSummary>,
    pub request_receipts: Vec<CloudSchedulerRequestReceipt>,
    pub response_receipts: Vec<CloudSchedulerResponseReceipt>,
    pub next_page_token_digest: Option<Digest>,
    pub cursor_chain_digest: Digest,
    pub failure_digest: Option<Digest>,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub proposal_only: bool,
    pub outcome_authority: bool,
    pub work_product_adoption: bool,
    pub digests: EvidenceDigests,
}

impl GcpCloudSchedulerEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operation: CloudSchedulerOperation,
        state: EvidenceState,
        jobs: Vec<SchedulerJobSummary>,
        request_receipts: Vec<CloudSchedulerRequestReceipt>,
        response_receipts: Vec<CloudSchedulerResponseReceipt>,
        next_page_token_digest: Option<Digest>,
        failure_digest: Option<Digest>,
        registration_digest: Digest,
        provider_digest: Digest,
        provider_revision: String,
        scope: &GcpCloudSchedulerScope,
        secret_reference_digest: Digest,
        duplicate_job_count: u16,
    ) -> Self {
        let mut digests = EvidenceDigests::new(
            provider_digest.clone(),
            scope.permission_digest(),
            scope.scope_digest(),
            secret_reference_digest,
        );
        let page_count = u16::try_from(response_receipts.len()).unwrap_or(u16::MAX);
        let job_count = u16::try_from(jobs.len()).unwrap_or(u16::MAX);
        let cursor_chain_digest = Digest::from_serializable(
            &request_receipts
                .iter()
                .map(|receipt| receipt.page_token_digest.clone())
                .collect::<Vec<_>>(),
        );
        let mut evidence = Self {
            schema_version: GCP_CLOUD_SCHEDULER_SCHEMA_VERSION.to_owned(),
            contract_version: GCP_CLOUD_SCHEDULER_CONTRACT_VERSION.to_owned(),
            plugin_version: GCP_CLOUD_SCHEDULER_PLUGIN_VERSION_TEXT.to_owned(),
            operation,
            state,
            scope_digest: scope.scope_digest(),
            permission_digest: scope.permission_digest(),
            registration_digest,
            provider_digest,
            provider_revision,
            project_revision: scope.project_revision(),
            mission_revision: scope.mission_revision(),
            work_product_revision: scope.work_product_revision(),
            page_count,
            job_count,
            duplicate_job_count,
            jobs,
            request_receipts,
            response_receipts,
            next_page_token_digest,
            cursor_chain_digest,
            failure_digest,
            native: false,
            connected: false,
            first_party: false,
            proposal_only: true,
            outcome_authority: false,
            work_product_adoption: false,
            digests,
        };
        digests = evidence.digests.clone();
        digests.evidence_digest = evidence.compute_evidence_digest();
        evidence.digests = digests;
        evidence
    }

    fn compute_evidence_digest(&self) -> Digest {
        #[derive(Serialize)]
        struct Input<'a> {
            schema_version: &'a str,
            contract_version: &'a str,
            plugin_version: &'a str,
            operation: CloudSchedulerOperation,
            state: EvidenceState,
            scope_digest: &'a Digest,
            permission_digest: &'a Digest,
            registration_digest: &'a Digest,
            provider_digest: &'a Digest,
            provider_revision: &'a str,
            project_revision: Revision,
            mission_revision: Revision,
            work_product_revision: Revision,
            page_count: u16,
            job_count: u16,
            duplicate_job_count: u16,
            jobs: &'a [SchedulerJobSummary],
            request_receipts: &'a [CloudSchedulerRequestReceipt],
            response_receipts: &'a [CloudSchedulerResponseReceipt],
            next_page_token_digest: &'a Option<Digest>,
            cursor_chain_digest: &'a Digest,
            failure_digest: &'a Option<Digest>,
            native: bool,
            connected: bool,
            first_party: bool,
            proposal_only: bool,
            outcome_authority: bool,
            work_product_adoption: bool,
            version_digest: &'a Digest,
            contract_digest: &'a Digest,
            secret_reference_digest: &'a Digest,
        }
        Digest::from_serializable(&Input {
            schema_version: &self.schema_version,
            contract_version: &self.contract_version,
            plugin_version: &self.plugin_version,
            operation: self.operation,
            state: self.state,
            scope_digest: &self.scope_digest,
            permission_digest: &self.permission_digest,
            registration_digest: &self.registration_digest,
            provider_digest: &self.provider_digest,
            provider_revision: &self.provider_revision,
            project_revision: self.project_revision,
            mission_revision: self.mission_revision,
            work_product_revision: self.work_product_revision,
            page_count: self.page_count,
            job_count: self.job_count,
            duplicate_job_count: self.duplicate_job_count,
            jobs: &self.jobs,
            request_receipts: &self.request_receipts,
            response_receipts: &self.response_receipts,
            next_page_token_digest: &self.next_page_token_digest,
            cursor_chain_digest: &self.cursor_chain_digest,
            failure_digest: &self.failure_digest,
            native: self.native,
            connected: self.connected,
            first_party: self.first_party,
            proposal_only: self.proposal_only,
            outcome_authority: self.outcome_authority,
            work_product_adoption: self.work_product_adoption,
            version_digest: &self.digests.version_digest,
            contract_digest: &self.digests.contract_digest,
            secret_reference_digest: &self.digests.secret_reference_digest,
        })
    }

    #[must_use]
    pub fn evidence_digest(&self) -> &Digest {
        &self.digests.evidence_digest
    }

    #[must_use]
    pub fn verify_digest(&self) -> bool {
        self.jobs.iter().all(SchedulerJobSummary::verify_digest)
            && !self.native
            && !self.connected
            && !self.first_party
            && self.proposal_only
            && !self.outcome_authority
            && !self.work_product_adoption
            && self.digests.evidence_digest == self.compute_evidence_digest()
    }

    #[must_use]
    pub fn is_native(&self) -> bool {
        self.native
    }

    #[must_use]
    pub fn is_connected(&self) -> bool {
        self.connected
    }
}

pub type GcpCloudSchedulerJobEvidence = GcpCloudSchedulerEvidence;
pub type GcpCloudSchedulerResultEvidence = GcpCloudSchedulerEvidence;
pub type CloudSchedulerEvidence = GcpCloudSchedulerEvidence;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadBounds {
    pub max_pages: u16,
    pub page_size: u16,
    pub max_jobs: u16,
}

impl ReadBounds {
    pub fn new(max_pages: u16, page_size: u16, max_jobs: u16) -> Result<Self, ModelError> {
        if max_pages == 0 || max_pages > MAX_PAGES {
            return Err(ModelError::OutsideBound { field: "max pages" });
        }
        if page_size == 0 || page_size > MAX_PAGE_SIZE {
            return Err(ModelError::OutsideBound { field: "page size" });
        }
        if max_jobs == 0 || usize::from(max_jobs) > MAX_JOBS {
            return Err(ModelError::OutsideBound { field: "max jobs" });
        }
        Ok(Self {
            max_pages,
            page_size,
            max_jobs,
        })
    }
}

impl Default for ReadBounds {
    fn default() -> Self {
        Self {
            max_pages: MAX_PAGES,
            page_size: MAX_PAGE_SIZE,
            max_jobs: u16::try_from(MAX_JOBS).expect("MAX_JOBS fits in u16"),
        }
    }
}

pub type GcpCloudSchedulerResultBounds = ReadBounds;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudSchedulerObservationRecord {
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub observation_revision: Revision,
    pub record_digest: Digest,
}

impl CloudSchedulerObservationRecord {
    pub(crate) fn new(
        evidence: &GcpCloudSchedulerEvidence,
        observation_revision: Revision,
    ) -> Self {
        let evidence_digest = evidence.evidence_digest().clone();
        let registration_digest = evidence.registration_digest.clone();
        let record_digest = Digest::from_serializable(&(
            &evidence_digest,
            &registration_digest,
            observation_revision,
        ));
        Self {
            evidence_digest,
            registration_digest,
            observation_revision,
            record_digest,
        }
    }

    #[must_use]
    pub fn verify_digest(&self) -> bool {
        self.record_digest
            == Digest::from_serializable(&(
                &self.evidence_digest,
                &self.registration_digest,
                self.observation_revision,
            ))
    }
}

pub type GcpCloudSchedulerObservationRecord = CloudSchedulerObservationRecord;

// Keep these constants referenced in the model so a version/provider drift is
// visible to strict builds even when only model types are consumed.
#[allow(dead_code)]
const _MODEL_VERSION_FENCE: (&str, &str, &str, &str) = (
    GCP_CLOUD_SCHEDULER_SCHEMA_VERSION,
    GCP_CLOUD_SCHEDULER_CONTRACT_VERSION,
    GCP_CLOUD_SCHEDULER_PROVIDER_ID,
    GCP_CLOUD_SCHEDULER_PROVIDER_VERSION_TEXT,
);
