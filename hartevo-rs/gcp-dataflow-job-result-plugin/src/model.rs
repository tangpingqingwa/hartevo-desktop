//! Bounded, typed models for the Google Cloud Dataflow job-result read seam.
//!
//! Provider payloads are deliberately not represented as public JSON models.
//! The provider parses only the allowlisted lifecycle, stage, and metric
//! fields and crosses the boundary with digests and bounded summaries.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    str::FromStr,
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::{GCP_DATAFLOW_JOB_RESULT_PLUGIN_VERSION_TEXT, GCP_DATAFLOW_JOB_RESULT_PROVIDER_ID};

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_DIGEST_INPUT_BYTES: usize = 1_048_576;
pub const MAX_STAGE_BYTES: usize = 256;
pub const MAX_METRIC_BYTES: usize = 256;
pub const MAX_OPAQUE_PAGE_TOKEN_BYTES: usize = 4_096;
pub const MAX_OPAQUE_FILTER_BYTES: usize = 4_096;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_PAGES: u16 = 16;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_JOBS: usize = 500;
pub const MAX_STAGES_PER_JOB: usize = 128;
pub const MAX_METRICS_PER_JOB: usize = 256;
pub const MAX_DIAGNOSTIC_BYTES: usize = 512;
pub const MAX_METRIC_VALUE_BYTES: usize = 128;

/// A lowercase SHA-256 digest used at every cross-boundary binding.
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
    ///
    /// # Panics
    ///
    /// Panics only if the caller supplies a value whose `Serialize`
    /// implementation fails. Values constructed by this crate are bounded
    /// and infallibly serializable.
    pub fn from_serializable<T: Serialize + ?Sized>(value: &T) -> Self {
        let bytes = serde_json::to_vec(value).expect("bounded Dataflow value serializes");
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
    #[error("permission scope is not exactly the read-only Dataflow job scope")]
    InvalidPermission,
    #[error("consent scope is not read-only or has expired")]
    InvalidConsent,
    #[error("Dataflow job timing is inconsistent")]
    InvalidTiming,
    #[error("Dataflow job payload drifted from the exact bound scope")]
    ScopeDrift,
    #[error("Dataflow stage or metric allowlist is invalid")]
    InvalidAllowlist,
    #[error("Dataflow registration is already revoked")]
    AlreadyRevoked,
    #[error("Dataflow registration or secret reference is not revoked")]
    NotRevoked,
    #[error("revision overflowed")]
    RevisionOverflow,
    #[error("digest input is too large")]
    DigestInputTooLarge,
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
        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/' | b':' | b'@')
    }) {
        return Err(ModelError::InvalidIdentifier { field });
    }
    Ok(())
}

macro_rules! bounded_identifier {
    ($name:ident, $field:literal, $maximum:expr) => {
        #[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
                let value = value.into();
                validate_text(&value, $field, $maximum, false)?;
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

        impl FromStr for $name {
            type Err = ModelError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

bounded_identifier!(ProjectId, "GCP project id", MAX_IDENTIFIER_BYTES);
bounded_identifier!(Location, "Dataflow location", MAX_IDENTIFIER_BYTES);
bounded_identifier!(JobId, "Dataflow job id", MAX_IDENTIFIER_BYTES);
bounded_identifier!(StageName, "Dataflow stage name", MAX_STAGE_BYTES);
bounded_identifier!(MetricName, "Dataflow metric name", MAX_METRIC_BYTES);

pub type GcpProjectId = ProjectId;
pub type GcpDataflowJobId = JobId;
pub type DataflowJobId = JobId;
pub type DataflowStageName = StageName;
pub type DataflowMetricName = MetricName;

/// A positive revision used in exact Project, Mission, Work Product, and job bindings.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(u64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, ModelError> {
        if value == 0 {
            return Err(ModelError::MustBePositive { field: "revision" });
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    pub fn next(self) -> Result<Self, ModelError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(ModelError::RevisionOverflow)
    }
}

impl fmt::Display for Revision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

// Bindings are written explicitly so their constructors retain the owned id.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectBinding {
    pub id: String,
    pub revision: Revision,
}

impl ProjectBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        let id = id.into();
        validate_identifier(&id, "Project binding id")?;
        Ok(Self {
            id,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionBinding {
    pub id: String,
    pub revision: Revision,
}

impl MissionBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        let id = id.into();
        validate_identifier(&id, "Mission binding id")?;
        Ok(Self {
            id,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkProductBinding {
    pub id: String,
    pub revision: Revision,
}

impl WorkProductBinding {
    pub fn new(id: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        let id = id.into();
        validate_identifier(&id, "Work Product binding id")?;
        Ok(Self {
            id,
            revision: Revision::new(revision)?,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

pub type Project = ProjectBinding;
pub type Mission = MissionBinding;
pub type WorkProduct = WorkProductBinding;
pub type ProjectIdentity = ProjectBinding;
pub type MissionIdentity = MissionBinding;
pub type WorkProductIdentity = WorkProductBinding;

/// The only pipeline types retained by this Layer-1 contract.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DataflowPipelineType {
    Batch,
    Streaming,
    Unknown,
}

impl DataflowPipelineType {
    #[must_use]
    pub fn from_provider(value: &str) -> Self {
        match value.trim().to_ascii_uppercase().as_str() {
            "BATCH" | "JOB_TYPE_BATCH" => Self::Batch,
            "STREAMING" | "JOB_TYPE_STREAMING" => Self::Streaming,
            _ => Self::Unknown,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Batch => "BATCH",
            Self::Streaming => "STREAMING",
            Self::Unknown => "UNKNOWN",
        }
    }

    #[must_use]
    pub fn digest(self) -> Digest {
        Digest::from_text(self.as_str())
    }
}

impl fmt::Display for DataflowPipelineType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(formatter)
    }
}

pub type PipelineType = DataflowPipelineType;

/// Exact job selection. `Any` is used only for a bounded list read.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum DataflowJobSelector {
    Any,
    Exact { job_id: JobId },
}

impl DataflowJobSelector {
    #[must_use]
    pub const fn any() -> Self {
        Self::Any
    }

    pub fn try_exact(value: impl Into<String>) -> Result<Self, ModelError> {
        Ok(Self::Exact {
            job_id: JobId::new(value)?,
        })
    }

    #[must_use]
    pub fn exact(job_id: JobId) -> Self {
        Self::Exact { job_id }
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
}

pub type JobSelector = DataflowJobSelector;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct StageAllowlist(pub BTreeSet<StageName>);

impl StageAllowlist {
    pub fn new<I, V>(values: I) -> Result<Self, ModelError>
    where
        I: IntoIterator<Item = V>,
        V: Into<String>,
    {
        let values = values
            .into_iter()
            .map(|value| StageName::new(value))
            .collect::<Result<BTreeSet<_>, _>>()?;
        if values.len() > MAX_STAGES_PER_JOB {
            return Err(ModelError::OutsideBound {
                field: "stage allowlist",
            });
        }
        Ok(Self(values))
    }

    #[must_use]
    pub fn empty() -> Self {
        Self(BTreeSet::new())
    }

    #[must_use]
    pub fn contains(&self, value: &str) -> bool {
        self.0.iter().any(|stage| stage.as_str() == value)
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Default for StageAllowlist {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct MetricAllowlist(pub BTreeSet<MetricName>);

impl MetricAllowlist {
    pub fn new<I, V>(values: I) -> Result<Self, ModelError>
    where
        I: IntoIterator<Item = V>,
        V: Into<String>,
    {
        let values = values
            .into_iter()
            .map(|value| MetricName::new(value))
            .collect::<Result<BTreeSet<_>, _>>()?;
        if values.len() > MAX_METRICS_PER_JOB {
            return Err(ModelError::OutsideBound {
                field: "metric allowlist",
            });
        }
        Ok(Self(values))
    }

    #[must_use]
    pub fn empty() -> Self {
        Self(BTreeSet::new())
    }

    #[must_use]
    pub fn contains(&self, value: &str) -> bool {
        self.0.iter().any(|metric| metric.as_str() == value)
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Default for MetricAllowlist {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionScope {
    pub actions: BTreeSet<String>,
}

impl PermissionScope {
    #[must_use]
    pub fn read_only() -> Self {
        Self {
            actions: [
                "dataflow.jobs.list",
                "dataflow.jobs.get",
                "dataflow.jobs.getMetrics",
                "mission.scope",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self != &Self::read_only() {
            return Err(ModelError::InvalidPermission);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }

    #[must_use]
    pub fn permissions(&self) -> &BTreeSet<String> {
        &self.actions
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentScope {
    pub id: String,
    pub revision: Revision,
    pub expires_at: DateTime<Utc>,
    pub read_only: bool,
}

impl ConsentScope {
    pub fn new(
        id: impl Into<String>,
        revision: u64,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, ModelError> {
        let id = id.into();
        validate_identifier(&id, "consent id")?;
        Ok(Self {
            id,
            revision: Revision::new(revision)?,
            expires_at,
            read_only: true,
        })
    }

    pub fn for_layer_one(
        id: impl Into<String>,
        revision: u64,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, ModelError> {
        Self::new(id, revision, expires_at)
    }

    pub fn validate_at(&self, now: DateTime<Utc>) -> Result<(), ModelError> {
        if !self.read_only || self.expires_at <= now {
            return Err(ModelError::InvalidConsent);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

/// The only credential kind accepted by this Layer-1 boundary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretReferenceKind {
    OAuth,
    ServiceAccount,
}

/// An opaque OAuth or service-account reference.
///
/// The supplied host-keyring handle is hashed at the input boundary and is
/// never retained, serialized, formatted, or placed in a request.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretReferenceKind,
    reference_digest: Digest,
    revision: Revision,
    scope_digest: Option<Digest>,
    revoked: bool,
}

impl SecretReference {
    /// Builds an unbound OAuth reference for compatibility with generic callers.
    pub fn new(handle: impl Into<String>, revision: u64) -> Result<Self, ModelError> {
        let handle = handle.into();
        Self::unbound(
            SecretReferenceKind::OAuth,
            handle.as_str(),
            Revision::new(revision)?,
        )
    }

    /// Builds an OAuth reference bound to the exact Dataflow scope.
    pub fn oauth(
        opaque_reference: impl AsRef<str>,
        scope: &GcpDataflowJobResultScope,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        Self::for_scope_kind(
            SecretReferenceKind::OAuth,
            opaque_reference,
            scope,
            revision,
        )
    }

    /// Builds a service-account reference bound to the exact Dataflow scope.
    pub fn service_account(
        opaque_reference: impl AsRef<str>,
        scope: &GcpDataflowJobResultScope,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        Self::for_scope_kind(
            SecretReferenceKind::ServiceAccount,
            opaque_reference,
            scope,
            revision,
        )
    }

    /// Builds an unbound reference of the selected authentication kind.
    pub fn unbound(
        kind: SecretReferenceKind,
        opaque_reference: impl AsRef<str>,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        Self::build(kind, opaque_reference.as_ref(), None, revision)
    }

    /// Builds the default OAuth reference bound to the exact Dataflow scope.
    pub fn for_scope(
        handle: impl Into<String>,
        revision: u64,
        scope: &GcpDataflowJobResultScope,
    ) -> Result<Self, ModelError> {
        let handle = handle.into();
        Self::for_scope_kind(
            SecretReferenceKind::OAuth,
            handle.as_str(),
            scope,
            Revision::new(revision)?,
        )
    }

    /// Builds a reference of the selected kind bound to the exact Dataflow scope.
    pub fn for_scope_kind(
        kind: SecretReferenceKind,
        opaque_reference: impl AsRef<str>,
        scope: &GcpDataflowJobResultScope,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        Self::build(
            kind,
            opaque_reference.as_ref(),
            Some(scope.scope_digest()),
            revision,
        )
    }

    fn build(
        kind: SecretReferenceKind,
        opaque_reference: &str,
        scope_digest: Option<Digest>,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        validate_text(
            opaque_reference,
            "opaque OAuth or service-account SecretReference",
            MAX_IDENTIFIER_BYTES,
            true,
        )?;
        if opaque_reference.len() > MAX_DIGEST_INPUT_BYTES {
            return Err(ModelError::DigestInputTooLarge);
        }
        let reference_digest = Digest::from_serializable(&(
            "opaque-secret-reference/v1",
            kind,
            opaque_reference,
            &scope_digest,
            revision,
        ));
        Ok(Self {
            kind,
            reference_digest,
            revision,
            scope_digest,
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
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn scope_digest(&self) -> Option<&Digest> {
        self.scope_digest.as_ref()
    }

    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn validate(&self, scope: &GcpDataflowJobResultScope) -> Result<(), ModelError> {
        if self.revoked
            || self
                .scope_digest
                .as_ref()
                .is_some_and(|digest| digest != &scope.scope_digest())
        {
            return Err(ModelError::ScopeDrift);
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<(), ModelError> {
        if self.revoked {
            return Err(ModelError::AlreadyRevoked);
        }
        self.revoked = true;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), ModelError> {
        if !self.revoked {
            return Err(ModelError::NotRevoked);
        }
        self.revoked = false;
        Ok(())
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("kind", &self.kind)
            .field("reference_digest", &self.reference_digest)
            .field("revision", &self.revision)
            .field("scope_digest", &self.scope_digest)
            .field("revoked", &self.revoked)
            .finish_non_exhaustive()
    }
}

pub type OAuthSecretReference = SecretReference;
pub type ServiceAccountSecretReference = SecretReference;
pub type GcpAuthKind = SecretReferenceKind;
pub type GoogleAuthKind = SecretReferenceKind;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DataflowJobState {
    Pending,
    Queued,
    Running,
    Cancellable,
    Draining,
    Drained,
    Done,
    Failed,
    Cancelled,
    Updated,
    Expired,
    Partial,
    AccessLost,
    ProviderUnknown,
    Tampered,
    Revoked,
}

impl DataflowJobState {
    #[must_use]
    pub fn from_provider(value: &str) -> Self {
        match value.trim().to_ascii_uppercase().as_str() {
            "JOB_STATE_PENDING" | "PENDING" => Self::Pending,
            "JOB_STATE_QUEUED" | "QUEUED" => Self::Queued,
            "JOB_STATE_RUNNING" | "RUNNING" => Self::Running,
            "JOB_STATE_CANCELLING" | "CANCELLING" => Self::Cancellable,
            "JOB_STATE_DRAINING" | "DRAINING" => Self::Draining,
            "JOB_STATE_DRAINED" | "DRAINED" => Self::Drained,
            "JOB_STATE_DONE" | "DONE" => Self::Done,
            "JOB_STATE_FAILED" | "FAILED" => Self::Failed,
            "JOB_STATE_CANCELLED" | "CANCELLED" => Self::Cancelled,
            "JOB_STATE_UPDATED" | "UPDATED" => Self::Updated,
            "JOB_STATE_EXPIRED" | "EXPIRED" => Self::Expired,
            _ => Self::ProviderUnknown,
        }
    }

    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Drained
                | Self::Done
                | Self::Failed
                | Self::Cancelled
                | Self::Updated
                | Self::Expired
        )
    }

    #[must_use]
    pub fn can_transition_to(self, next: Self) -> bool {
        if self == next {
            return true;
        }
        if matches!(
            next,
            Self::Partial
                | Self::AccessLost
                | Self::ProviderUnknown
                | Self::Tampered
                | Self::Revoked
        ) {
            return true;
        }
        match self {
            Self::Pending => matches!(
                next,
                Self::Queued | Self::Running | Self::Cancellable | Self::Failed | Self::Expired
            ),
            Self::Queued => matches!(
                next,
                Self::Running | Self::Cancellable | Self::Failed | Self::Expired
            ),
            Self::Running => matches!(
                next,
                Self::Cancellable
                    | Self::Draining
                    | Self::Drained
                    | Self::Done
                    | Self::Failed
                    | Self::Cancelled
                    | Self::Updated
                    | Self::Expired
            ),
            Self::Cancellable => matches!(next, Self::Cancelled | Self::Draining | Self::Failed),
            Self::Draining => matches!(next, Self::Drained | Self::Failed | Self::Cancelled),
            Self::Drained
            | Self::Done
            | Self::Failed
            | Self::Cancelled
            | Self::Updated
            | Self::Expired
            | Self::Partial
            | Self::AccessLost
            | Self::ProviderUnknown
            | Self::Tampered
            | Self::Revoked => false,
        }
    }

    pub fn validate_transition(self, next: Self) -> Result<(), ModelError> {
        self.can_transition_to(next)
            .then_some(())
            .ok_or(ModelError::ScopeDrift)
    }
}

pub type JobState = DataflowJobState;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    Complete,
    Ready,
    Partial,
    Stale,
    AccessLost,
    NotFound,
    Conflict,
    RateLimited,
    TimedOut,
    ProviderUnknown,
    Tampered,
    Replayed,
    RegistrationRevoked,
}

pub type DataflowEvidenceState = EvidenceState;

impl EvidenceState {
    #[must_use]
    pub const fn is_non_adoptable(self) -> bool {
        true
    }

    #[must_use]
    pub const fn is_review_eligible(self) -> bool {
        matches!(self, Self::Complete | Self::Ready)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DataflowOperation {
    ListJobs,
    GetJob,
    GetMetrics,
}

impl DataflowOperation {
    #[must_use]
    pub const fn is_list(self) -> bool {
        matches!(self, Self::ListJobs)
    }

    #[must_use]
    pub const fn is_get(self) -> bool {
        matches!(self, Self::GetJob)
    }

    #[must_use]
    pub const fn is_metrics(self) -> bool {
        matches!(self, Self::GetMetrics)
    }
}

pub type JobOperation = DataflowOperation;

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
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fixture => "fixture",
            Self::Recording => "recording",
            Self::Loopback => "loopback",
            Self::BlockedEnv => "BLOCKED_ENV",
        }
    }

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
}

impl fmt::Display for TransportProvenance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(formatter)
    }
}

/// Exact scope for every Dataflow read and resulting Mission projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpDataflowJobResultScope {
    pub gcp_project: ProjectId,
    pub location: Location,
    pub job_selector: DataflowJobSelector,
    pub pipeline_type: DataflowPipelineType,
    pub stage_allowlist: StageAllowlist,
    pub metric_allowlist: MetricAllowlist,
    pub job_revision: Revision,
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub permission: PermissionScope,
    pub consent: ConsentScope,
}

impl GcpDataflowJobResultScope {
    pub fn new(
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
        gcp_project: impl Into<String>,
        location: impl Into<String>,
        job_selector: DataflowJobSelector,
        pipeline_type: DataflowPipelineType,
        stage_allowlist: StageAllowlist,
        metric_allowlist: MetricAllowlist,
        job_revision: u64,
        permission: PermissionScope,
        consent: ConsentScope,
    ) -> Result<Self, ModelError> {
        let scope = Self {
            gcp_project: ProjectId::new(gcp_project)?,
            location: Location::new(location)?,
            job_selector,
            pipeline_type,
            stage_allowlist,
            metric_allowlist,
            job_revision: Revision::new(job_revision)?,
            project,
            mission,
            work_product,
            permission,
            consent,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn read_only<I, V, J, W>(
        project: ProjectBinding,
        mission: MissionBinding,
        work_product: WorkProductBinding,
        gcp_project: impl Into<String>,
        location: impl Into<String>,
        job_selector: DataflowJobSelector,
        pipeline_type: DataflowPipelineType,
        stages: I,
        metrics: J,
        job_revision: u64,
        consent: ConsentScope,
    ) -> Result<Self, ModelError>
    where
        I: IntoIterator<Item = V>,
        V: Into<String>,
        J: IntoIterator<Item = W>,
        W: Into<String>,
    {
        Self::new(
            project,
            mission,
            work_product,
            gcp_project,
            location,
            job_selector,
            pipeline_type,
            StageAllowlist::new(stages)?,
            MetricAllowlist::new(metrics)?,
            job_revision,
            PermissionScope::read_only(),
            consent,
        )
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.permission.validate()?;
        if self.stage_allowlist.len() > MAX_STAGES_PER_JOB
            || self.metric_allowlist.len() > MAX_METRICS_PER_JOB
        {
            return Err(ModelError::InvalidAllowlist);
        }
        Ok(())
    }

    #[must_use]
    pub fn scope_digest(&self) -> Digest {
        Digest::from_serializable(self)
    }

    #[must_use]
    pub fn permission_digest(&self) -> Digest {
        self.permission.digest()
    }

    #[must_use]
    pub fn project_id(&self) -> &ProjectId {
        &self.gcp_project
    }

    #[must_use]
    pub fn job(&self) -> &DataflowJobSelector {
        &self.job_selector
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.job_revision
    }

    #[must_use]
    pub fn pipeline_type_digest(&self) -> Digest {
        self.pipeline_type.digest()
    }

    #[must_use]
    pub fn stage_allowlist_digest(&self) -> Digest {
        self.stage_allowlist.digest()
    }

    #[must_use]
    pub fn metric_allowlist_digest(&self) -> Digest {
        self.metric_allowlist.digest()
    }

    #[must_use]
    pub fn matches_job(&self, job: &DataflowJobSummary) -> bool {
        job.project_id == self.gcp_project
            && job.location == self.location
            && job.pipeline_type == self.pipeline_type
            && job.revision == self.job_revision
            && self
                .job_selector
                .job_id()
                .is_none_or(|job_id| job_id == &job.job_id)
    }
}

pub type GcpDataflowScope = GcpDataflowJobResultScope;
pub type DataflowJobResultScope = GcpDataflowJobResultScope;
pub type GcpDataflowJobResultResultScope = GcpDataflowJobResultScope;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataflowStageSummary {
    pub stage_digest: Digest,
    pub state: Option<DataflowJobState>,
    pub metric_count: u16,
}

impl DataflowStageSummary {
    pub fn new(
        stage_name: &str,
        state: Option<DataflowJobState>,
        metric_count: u16,
    ) -> Result<Self, ModelError> {
        StageName::new(stage_name)?;
        Ok(Self {
            stage_digest: Digest::from_text(stage_name),
            state,
            metric_count,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataflowMetricSummary {
    pub metric_name_digest: Digest,
    pub metric_digest: Digest,
    pub value_digest: Digest,
    pub integer_value: Option<i64>,
    pub decimal_value: Option<String>,
    pub unit_digest: Option<Digest>,
    pub tentative: bool,
    pub update_time: Option<DateTime<Utc>>,
}

impl DataflowMetricSummary {
    pub fn new(
        metric_name: &str,
        scalar: Option<MetricScalar>,
        unit: Option<&str>,
        tentative: bool,
        update_time: Option<DateTime<Utc>>,
    ) -> Result<Self, ModelError> {
        MetricName::new(metric_name)?;
        let value_digest = Digest::from_serializable(&scalar);
        let (integer_value, decimal_value) = match scalar {
            Some(MetricScalar::Integer(value)) => (Some(value), None),
            Some(MetricScalar::Decimal(value)) => (None, Some(value)),
            None => (None, None),
        };
        let unit_digest = unit.map(Digest::from_text);
        let metric_digest = Digest::from_serializable(&(
            metric_name,
            &value_digest,
            &unit_digest,
            tentative,
            update_time,
        ));
        Ok(Self {
            metric_name_digest: Digest::from_text(metric_name),
            metric_digest,
            value_digest,
            integer_value,
            decimal_value,
            unit_digest,
            tentative,
            update_time,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        self.metric_digest.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum MetricScalar {
    Integer(i64),
    Decimal(String),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataflowJobSummary {
    pub job_id: JobId,
    pub project_id: ProjectId,
    pub location: Location,
    pub pipeline_type: DataflowPipelineType,
    pub revision: Revision,
    pub state: DataflowJobState,
    pub create_time: Option<DateTime<Utc>>,
    pub start_time: Option<DateTime<Utc>>,
    pub state_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub name_digest: Option<Digest>,
    pub replacement_job_digest: Option<Digest>,
    pub stages: Vec<DataflowStageSummary>,
    pub error_digest: Option<Digest>,
    pub job_digest: Digest,
}

impl DataflowJobSummary {
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        job_id: JobId,
        project_id: ProjectId,
        location: Location,
        pipeline_type: DataflowPipelineType,
        revision: Revision,
        state: DataflowJobState,
        create_time: Option<DateTime<Utc>>,
        start_time: Option<DateTime<Utc>>,
        state_time: Option<DateTime<Utc>>,
        end_time: Option<DateTime<Utc>>,
        name_digest: Option<Digest>,
        replacement_job_digest: Option<Digest>,
        stages: Vec<DataflowStageSummary>,
        error_digest: Option<Digest>,
    ) -> Self {
        let job_digest = Digest::from_serializable(&(
            &job_id,
            &project_id,
            &location,
            pipeline_type,
            revision,
            state,
            create_time,
            start_time,
            state_time,
            end_time,
            &name_digest,
            &replacement_job_digest,
            &stages,
            &error_digest,
        ));
        Self {
            job_id,
            project_id,
            location,
            pipeline_type,
            revision,
            state,
            create_time,
            start_time,
            state_time,
            end_time,
            name_digest,
            replacement_job_digest,
            stages,
            error_digest,
            job_digest,
        }
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        self.job_digest.clone()
    }

    #[must_use]
    pub fn verify_digest(&self) -> bool {
        let candidate = Self::new(
            self.job_id.clone(),
            self.project_id.clone(),
            self.location.clone(),
            self.pipeline_type,
            self.revision,
            self.state,
            self.create_time,
            self.start_time,
            self.state_time,
            self.end_time,
            self.name_digest.clone(),
            self.replacement_job_digest.clone(),
            self.stages.clone(),
            self.error_digest.clone(),
        );
        candidate.job_digest == self.job_digest
    }

    #[must_use]
    pub fn matches_scope(&self, scope: &GcpDataflowJobResultScope) -> bool {
        scope.matches_job(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseStatus {
    Complete,
    Partial,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataflowRequestReceipt {
    pub operation: DataflowOperation,
    pub method: String,
    pub path_digest: Digest,
    pub project_digest: Digest,
    pub location_digest: Digest,
    pub job_digest: Option<Digest>,
    pub filter_digest: Digest,
    pub page_token_digest: Option<Digest>,
    pub request_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataflowResponseReceipt {
    pub status_code: u16,
    pub body_digest: Digest,
    pub body_bytes: usize,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceDigests {
    pub version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub job_digest: Digest,
    pub stage_digest: Digest,
    pub metric_digest: Digest,
    pub request_digest: Digest,
    pub response_digest: Digest,
    pub result_digest: Digest,
    pub evidence_digest: Digest,
}

impl EvidenceDigests {
    #[must_use]
    pub fn new(
        provider_digest: Digest,
        permission_digest: Digest,
        scope_digest: Digest,
        registration_digest: Digest,
    ) -> Self {
        Self {
            version_digest: Digest::from_text(GCP_DATAFLOW_JOB_RESULT_PLUGIN_VERSION_TEXT),
            contract_digest: crate::contract_digest(),
            provider_digest,
            api_digest: Digest::from_text(crate::provider::GCP_DATAFLOW_API_REVISION),
            permission_digest,
            scope_digest,
            registration_digest,
            job_digest: Digest::from_text("empty-dataflow-job-set"),
            stage_digest: Digest::from_text("empty-dataflow-stage-set"),
            metric_digest: Digest::from_text("empty-dataflow-metric-set"),
            request_digest: Digest::from_text("empty-dataflow-request-set"),
            response_digest: Digest::from_text("empty-dataflow-response-set"),
            result_digest: Digest::from_text("empty-dataflow-result-set"),
            evidence_digest: Digest::from_text("unsealed-dataflow-evidence"),
        }
    }
}

/// Bounded review-only evidence delivered to a Mission consumer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataflowEvidence {
    pub schema_version: String,
    pub contract_version: String,
    pub plugin_version: String,
    pub operation: DataflowOperation,
    pub state: EvidenceState,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub page_count: u16,
    pub job_count: u16,
    pub metric_count: u16,
    pub jobs: Vec<DataflowJobSummary>,
    pub metrics: Vec<DataflowMetricSummary>,
    pub request_receipts: Vec<DataflowRequestReceipt>,
    pub response_receipts: Vec<DataflowResponseReceipt>,
    pub record_digests: Vec<Digest>,
    pub failure_digest: Option<Digest>,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub proposal_only: bool,
    pub outcome_authority: bool,
    pub work_product_adoption: bool,
    pub digests: EvidenceDigests,
}

impl DataflowEvidence {
    #[must_use]
    pub fn evidence_digest(&self) -> &Digest {
        &self.digests.evidence_digest
    }

    #[must_use]
    pub fn calculate_evidence_digest(&self) -> Digest {
        #[derive(Serialize)]
        struct EvidenceDigestInput<'a> {
            schema_version: &'a str,
            contract_version: &'a str,
            plugin_version: &'a str,
            operation: DataflowOperation,
            state: EvidenceState,
            scope_digest: &'a Digest,
            permission_digest: &'a Digest,
            registration_digest: &'a Digest,
            provider_digest: &'a Digest,
            page_count: u16,
            job_count: u16,
            metric_count: u16,
            jobs: &'a [DataflowJobSummary],
            metrics: &'a [DataflowMetricSummary],
            request_receipts: &'a [DataflowRequestReceipt],
            response_receipts: &'a [DataflowResponseReceipt],
            record_digests: &'a [Digest],
            failure_digest: &'a Option<Digest>,
            native: bool,
            connected: bool,
            first_party: bool,
            provider_receipt: bool,
            proposal_only: bool,
            outcome_authority: bool,
            work_product_adoption: bool,
        }
        Digest::from_serializable(&EvidenceDigestInput {
            schema_version: &self.schema_version,
            contract_version: &self.contract_version,
            plugin_version: &self.plugin_version,
            operation: self.operation,
            state: self.state,
            scope_digest: &self.scope_digest,
            permission_digest: &self.permission_digest,
            registration_digest: &self.registration_digest,
            provider_digest: &self.provider_digest,
            page_count: self.page_count,
            job_count: self.job_count,
            metric_count: self.metric_count,
            jobs: &self.jobs,
            metrics: &self.metrics,
            request_receipts: &self.request_receipts,
            response_receipts: &self.response_receipts,
            record_digests: &self.record_digests,
            failure_digest: &self.failure_digest,
            native: self.native,
            connected: self.connected,
            first_party: self.first_party,
            provider_receipt: self.provider_receipt,
            proposal_only: self.proposal_only,
            outcome_authority: self.outcome_authority,
            work_product_adoption: self.work_product_adoption,
        })
    }

    #[must_use]
    pub fn verify_digest(&self) -> bool {
        !self.native
            && !self.connected
            && !self.first_party
            && !self.provider_receipt
            && !self.outcome_authority
            && !self.work_product_adoption
            && self.digests.version_digest == crate::plugin_version_digest()
            && self.digests.contract_digest == crate::contract_digest()
            && self.digests.api_digest
                == Digest::from_text(crate::provider::GCP_DATAFLOW_API_REVISION)
            && self.digests.permission_digest == self.permission_digest
            && self.digests.scope_digest == self.scope_digest
            && self.digests.registration_digest == self.registration_digest
            && self.digests.job_digest == aggregate_job_digest(&self.jobs)
            && self.digests.stage_digest == aggregate_stage_digest(&self.jobs)
            && self.digests.metric_digest == aggregate_metric_digest(&self.metrics)
            && self.digests.request_digest == aggregate_request_digest(&self.request_receipts)
            && self.digests.response_digest == aggregate_response_digest(&self.response_receipts)
            && self.digests.result_digest == Digest::from_serializable(&(&self.jobs, &self.metrics))
            && self.digests.evidence_digest == self.calculate_evidence_digest()
            && self.jobs.iter().all(DataflowJobSummary::verify_digest)
    }

    #[must_use]
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

/// A compact summary of a provider observation, useful for idempotency records.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DataflowObservationRecord {
    pub operation: DataflowOperation,
    pub record_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub replayed: bool,
    pub provenance: TransportProvenance,
}

/// Compute stable aggregate digests without depending on provider object order.
#[must_use]
pub fn aggregate_job_digest(jobs: &[DataflowJobSummary]) -> Digest {
    let mut values = jobs
        .iter()
        .map(DataflowJobSummary::digest)
        .collect::<Vec<_>>();
    values.sort();
    Digest::from_serializable(&values)
}

#[must_use]
pub fn aggregate_stage_digest(jobs: &[DataflowJobSummary]) -> Digest {
    let mut values = jobs
        .iter()
        .flat_map(|job| job.stages.iter().map(DataflowStageSummary::digest))
        .collect::<Vec<_>>();
    values.sort();
    Digest::from_serializable(&values)
}

#[must_use]
pub fn aggregate_metric_digest(metrics: &[DataflowMetricSummary]) -> Digest {
    let mut values = metrics
        .iter()
        .map(DataflowMetricSummary::digest)
        .collect::<Vec<_>>();
    values.sort();
    Digest::from_serializable(&values)
}

#[must_use]
pub fn aggregate_request_digest(receipts: &[DataflowRequestReceipt]) -> Digest {
    Digest::from_serializable(receipts)
}

#[must_use]
pub fn aggregate_response_digest(receipts: &[DataflowResponseReceipt]) -> Digest {
    Digest::from_serializable(receipts)
}

#[must_use]
pub fn job_state_digest(state: DataflowJobState) -> Digest {
    Digest::from_serializable(&state)
}

#[must_use]
pub fn version_digest() -> Digest {
    Digest::from_text(GCP_DATAFLOW_JOB_RESULT_PLUGIN_VERSION_TEXT)
}

#[must_use]
pub fn provider_id_digest() -> Digest {
    Digest::from_text(GCP_DATAFLOW_JOB_RESULT_PROVIDER_ID)
}

// Keep BTreeMap in the module's public type vocabulary for consumers that need
// deterministic keyed projections without exposing provider payloads.
pub type DeterministicDigestMap = BTreeMap<String, Digest>;
