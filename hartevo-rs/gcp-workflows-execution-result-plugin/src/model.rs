//! Bounded, typed models for the Google Cloud Workflows execution read seam.
//!
//! The model deliberately has no representation for workflow arguments,
//! results, definitions, labels, or stack traces.  Provider payloads cross
//! the redaction boundary as digests and typed presence/state metadata only.

use std::{collections::BTreeSet, fmt, str::FromStr};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

use crate::GCP_WORKFLOWS_EXECUTION_PLUGIN_VERSION_TEXT;

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_STEP_NAME_BYTES: usize = 256;
pub const MAX_PAGES: u16 = 16;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_EXECUTIONS: usize = 500;
pub const MAX_STEPS_PER_EXECUTION: usize = 256;
pub const MAX_OPAQUE_CURSOR_BYTES: usize = 4096;
pub const MAX_DIGEST_INPUT_BYTES: usize = 32 * 1024;
pub const MAX_RETRY_COUNT: u16 = 1024;

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
    #[error("{field} must be positive")]
    MustBePositive { field: &'static str },
    #[error("{field} is not a lowercase SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("revision overflowed")]
    RevisionOverflow,
    #[error("scope contains a drifted or invalid permission")]
    InvalidPermission,
    #[error("scope contains an invalid read-only consent")]
    InvalidConsent,
    #[error("execution timing is inconsistent")]
    InvalidTiming,
    #[error("execution contains too many steps")]
    TooManySteps,
    #[error("execution retry metadata is outside the Layer-1 bound")]
    InvalidRetryMetadata,
    #[error("execution payload digest input is too large")]
    DigestInputTooLarge,
    #[error("execution metadata is inconsistent with its state")]
    InvalidExecutionMetadata,
    #[error("registration is already revoked")]
    AlreadyRevoked,
    #[error("registration is not revoked")]
    NotRevoked,
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
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/'))
    {
        return Err(ModelError::InvalidIdentifier { field });
    }
    Ok(())
}

/// A lowercase SHA-256 digest used for every cross-boundary binding.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Self {
        Self(hex::encode(Sha256::digest(bytes.as_ref())))
    }

    pub fn from_text(value: impl AsRef<[u8]>) -> Self {
        Self::from_bytes(value)
    }

    pub fn from_serializable<T: Serialize>(value: &T) -> Self {
        let bytes = serde_json::to_vec(value).expect("bounded GCP Workflows values serialize");
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

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub const fn len(&self) -> usize {
        64
    }

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

            pub fn as_str(&self) -> &str {
                &self.0
            }

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

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self::new(value).expect("typed identifier conversion must be validated first")
            }
        }

        impl From<String> for $name {
            fn from(value: String) -> Self {
                Self::new(value).expect("typed identifier conversion must be validated first")
            }
        }
    };
}

bounded_identifier!(ProjectId, "project id", MAX_IDENTIFIER_BYTES);
bounded_identifier!(Location, "location", MAX_IDENTIFIER_BYTES);
bounded_identifier!(WorkflowId, "workflow id", MAX_IDENTIFIER_BYTES);
bounded_identifier!(
    WorkflowRevisionId,
    "workflow revision id",
    MAX_IDENTIFIER_BYTES
);
bounded_identifier!(ExecutionId, "execution id", MAX_IDENTIFIER_BYTES);
bounded_identifier!(MissionId, "mission id", MAX_IDENTIFIER_BYTES);
bounded_identifier!(WorkProductId, "work product id", MAX_IDENTIFIER_BYTES);
bounded_identifier!(StepName, "step name", MAX_STEP_NAME_BYTES);

pub type GcpProjectId = ProjectId;
pub type GcpWorkflowId = WorkflowId;
pub type GcpExecutionId = ExecutionId;
pub type WorkflowRevision = WorkflowRevisionId;
pub type ExecutionName = ExecutionId;

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

    pub fn next(self) -> Result<Self, ModelError> {
        Self::new(self.0.checked_add(1).ok_or(ModelError::RevisionOverflow)?)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectBinding {
    pub id: ProjectId,
    pub revision: Revision,
}

impl ProjectBinding {
    pub fn new(id: impl Into<ProjectId>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            id: id.into(),
            revision: Revision::new(revision)?,
        })
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.id
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionBinding {
    pub id: MissionId,
    pub revision: Revision,
}

impl MissionBinding {
    pub fn new(id: impl Into<MissionId>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            id: id.into(),
            revision: Revision::new(revision)?,
        })
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.id
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkProductBinding {
    pub id: WorkProductId,
    pub revision: Revision,
}

impl WorkProductBinding {
    pub fn new(id: impl Into<WorkProductId>, revision: u64) -> Result<Self, ModelError> {
        Ok(Self {
            id: id.into(),
            revision: Revision::new(revision)?,
        })
    }

    pub fn work_product_id(&self) -> &WorkProductId {
        &self.id
    }

    pub const fn revision(&self) -> Revision {
        self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkflowBinding {
    pub id: WorkflowId,
    pub revision: WorkflowRevisionId,
}

impl WorkflowBinding {
    pub fn new(
        id: impl Into<WorkflowId>,
        revision: impl Into<WorkflowRevisionId>,
    ) -> Result<Self, ModelError> {
        Ok(Self {
            id: id.into(),
            revision: revision.into(),
        })
    }

    pub fn workflow_id(&self) -> &WorkflowId {
        &self.id
    }

    pub fn workflow_revision(&self) -> &WorkflowRevisionId {
        &self.revision
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum ExecutionSelector {
    Any,
    Exact { id: ExecutionId },
}

impl ExecutionSelector {
    pub const fn any() -> Self {
        Self::Any
    }

    pub fn exact(id: impl Into<ExecutionId>) -> Self {
        Self::Exact { id: id.into() }
    }

    pub fn id(&self) -> Option<&ExecutionId> {
        match self {
            Self::Any => None,
            Self::Exact { id } => Some(id),
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }

    pub fn matches(&self, id: &ExecutionId) -> bool {
        self.id().is_none_or(|expected| expected == id)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretReferenceKind {
    OAuth,
    ServiceAccount,
}

/// A host-keyring reference.  The opaque identifier is hashed at the input
/// boundary and is never retained, serialized, or included in Debug output.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretReference {
    kind: SecretReferenceKind,
    reference_digest: Digest,
    scope_digest: Option<Digest>,
    revision: Revision,
    revoked: bool,
}

impl SecretReference {
    pub fn oauth(
        opaque_reference: impl AsRef<str>,
        scope: &GcpWorkflowsScope,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        Self::for_scope(
            SecretReferenceKind::OAuth,
            opaque_reference,
            scope,
            revision,
        )
    }

    pub fn service_account(
        opaque_reference: impl AsRef<str>,
        scope: &GcpWorkflowsScope,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        Self::for_scope(
            SecretReferenceKind::ServiceAccount,
            opaque_reference,
            scope,
            revision,
        )
    }

    pub fn new(
        opaque_reference: impl AsRef<str>,
        scope: &GcpWorkflowsScope,
        revision: Revision,
        kind: SecretReferenceKind,
    ) -> Result<Self, ModelError> {
        Self::for_scope(kind, opaque_reference, scope, revision)
    }

    pub fn unbound(
        kind: SecretReferenceKind,
        opaque_reference: impl AsRef<str>,
        revision: Revision,
    ) -> Result<Self, ModelError> {
        Self::build(kind, opaque_reference.as_ref(), None, revision)
    }

    pub fn for_scope(
        kind: SecretReferenceKind,
        opaque_reference: impl AsRef<str>,
        scope: &GcpWorkflowsScope,
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
            "hartevo:gcp-workflows-secret-reference:v1",
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

    pub const fn kind(&self) -> SecretReferenceKind {
        self.kind
    }

    pub fn reference_digest(&self) -> &Digest {
        &self.reference_digest
    }

    pub fn digest(&self) -> Digest {
        self.reference_digest.clone()
    }

    pub fn scope_digest(&self) -> Option<&Digest> {
        self.scope_digest.as_ref()
    }

    pub const fn revision(&self) -> Revision {
        self.revision
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionAction {
    WorkflowsExecutionsList,
    WorkflowsExecutionsGet,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionScope {
    pub actions: BTreeSet<PermissionAction>,
    pub boundary_digest: Digest,
    pub external_writes: bool,
}

impl PermissionScope {
    pub fn read_only() -> Self {
        let actions = BTreeSet::from([
            PermissionAction::WorkflowsExecutionsGet,
            PermissionAction::WorkflowsExecutionsList,
        ]);
        let mut permission = Self {
            actions,
            boundary_digest: Digest::from_text("placeholder"),
            external_writes: false,
        };
        permission.boundary_digest = permission.compute_digest();
        permission
    }

    pub fn new(actions: BTreeSet<PermissionAction>) -> Result<Self, ModelError> {
        let permission = Self {
            actions,
            boundary_digest: Digest::from_text("placeholder"),
            external_writes: false,
        };
        permission.validate()?;
        let mut permission = permission;
        permission.boundary_digest = permission.compute_digest();
        Ok(permission)
    }

    pub fn allows(&self, action: PermissionAction) -> bool {
        self.actions.contains(&action)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.external_writes
            || !self.allows(PermissionAction::WorkflowsExecutionsList)
            || !self.allows(PermissionAction::WorkflowsExecutionsGet)
            || self.actions.len() != 2
            || self.boundary_digest != self.compute_digest()
        {
            return Err(ModelError::InvalidPermission);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&(&self.actions, self.external_writes))
    }

    pub fn digest(&self) -> Digest {
        self.boundary_digest.clone()
    }
}

pub type PermissionBinding = PermissionScope;
pub type GcpWorkflowsPermission = PermissionScope;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentScope {
    pub consent_digest: Digest,
    pub revision: Revision,
    pub read_only: bool,
}

impl ConsentScope {
    pub fn new(reference: impl AsRef<str>, revision: u64) -> Result<Self, ModelError> {
        let reference = reference.as_ref();
        validate_text(reference, "consent reference", MAX_IDENTIFIER_BYTES, true)?;
        let consent = Self {
            consent_digest: Digest::from_text(reference),
            revision: Revision::new(revision)?,
            read_only: true,
        };
        consent.validate()?;
        Ok(consent)
    }

    pub fn read_only() -> Self {
        Self::new("hartevo:gcp-workflows-read-only-consent", 1)
            .expect("constant read-only consent is valid")
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if !self.read_only || !is_digest(self.consent_digest.as_str()) {
            Err(ModelError::InvalidConsent)
        } else {
            Ok(())
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpWorkflowsScope {
    pub project: ProjectBinding,
    pub location: Location,
    pub workflow: WorkflowBinding,
    pub execution: ExecutionSelector,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub permission: PermissionScope,
    pub consent: ConsentScope,
}

impl GcpWorkflowsScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        project: ProjectBinding,
        location: impl Into<Location>,
        workflow: WorkflowBinding,
        execution: ExecutionSelector,
        mission: MissionBinding,
        work_product: WorkProductBinding,
        permission: PermissionScope,
        consent: ConsentScope,
    ) -> Result<Self, ModelError> {
        let scope = Self {
            project,
            location: location.into(),
            workflow,
            execution,
            mission,
            work_product,
            permission,
            consent,
        };
        scope.validate()?;
        Ok(scope)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn read_only(
        project: ProjectBinding,
        location: impl Into<Location>,
        workflow: WorkflowBinding,
        execution: ExecutionSelector,
        mission: MissionBinding,
        work_product: WorkProductBinding,
    ) -> Result<Self, ModelError> {
        Self::new(
            project,
            location,
            workflow,
            execution,
            mission,
            work_product,
            PermissionScope::read_only(),
            ConsentScope::read_only(),
        )
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.permission.validate()?;
        self.consent.validate()?;
        Ok(())
    }

    pub fn scope_digest(&self) -> Digest {
        Digest::from_serializable(self)
    }

    pub fn digest(&self) -> Digest {
        self.scope_digest()
    }

    pub fn permission_digest(&self) -> Digest {
        self.permission.digest()
    }

    pub fn execution_digest(&self) -> Digest {
        self.execution.digest()
    }

    pub fn workflow_digest(&self) -> Digest {
        self.workflow.digest()
    }

    pub fn project_id(&self) -> &ProjectId {
        self.project.project_id()
    }

    pub fn mission_id(&self) -> &MissionId {
        self.mission.mission_id()
    }
}

pub type GcpWorkflowsExecutionScope = GcpWorkflowsScope;
pub type WorkflowsScope = GcpWorkflowsScope;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionState {
    StateUnspecified,
    Queued,
    Active,
    Succeeded,
    Failed,
    Cancelled,
    Unavailable,
}

impl ExecutionState {
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Cancelled | Self::Unavailable
        )
    }

    pub const fn is_known(self) -> bool {
        !matches!(self, Self::StateUnspecified)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StepState {
    Unknown,
    Queued,
    Running,
    Succeeded,
    Failed,
    Skipped,
    Cancelled,
    RetryPending,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminationKind {
    NotTerminated,
    Completed,
    Failed,
    Cancelled,
    Unavailable,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionTiming {
    pub create_time: DateTime<Utc>,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub duration_millis: Option<u64>,
}

impl ExecutionTiming {
    pub fn new(
        create_time: DateTime<Utc>,
        start_time: Option<DateTime<Utc>>,
        end_time: Option<DateTime<Utc>>,
        duration_millis: Option<u64>,
    ) -> Result<Self, ModelError> {
        if start_time.is_some_and(|start| start < create_time)
            || end_time
                .is_some_and(|end| start_time.is_some_and(|start| end < start) || end < create_time)
        {
            return Err(ModelError::InvalidTiming);
        }
        Ok(Self {
            create_time,
            start_time,
            end_time,
            duration_millis,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TerminationMetadata {
    pub kind: TerminationKind,
    pub attempt_count: u16,
    pub retry_count: u16,
    pub reason_digest: Option<Digest>,
}

impl TerminationMetadata {
    pub fn new(
        kind: TerminationKind,
        attempt_count: u16,
        retry_count: u16,
        reason_digest: Option<Digest>,
    ) -> Result<Self, ModelError> {
        if attempt_count == 0
            || retry_count > MAX_RETRY_COUNT
            || retry_count >= attempt_count && kind != TerminationKind::NotTerminated
        {
            return Err(ModelError::InvalidRetryMetadata);
        }
        Ok(Self {
            kind,
            attempt_count,
            retry_count,
            reason_digest,
        })
    }

    pub fn not_terminated() -> Self {
        Self {
            kind: TerminationKind::NotTerminated,
            attempt_count: 1,
            retry_count: 0,
            reason_digest: None,
        }
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StepMetadata {
    pub name: StepName,
    pub state: StepState,
    pub attempt_count: u16,
    pub retry_count: u16,
    pub result_digest: Option<Digest>,
    pub error_digest: Option<Digest>,
    pub metadata_digest: Digest,
}

impl StepMetadata {
    pub fn new(
        name: impl Into<StepName>,
        state: StepState,
        attempt_count: u16,
        retry_count: u16,
        result_digest: Option<Digest>,
        error_digest: Option<Digest>,
    ) -> Result<Self, ModelError> {
        if attempt_count == 0 || retry_count > MAX_RETRY_COUNT || retry_count >= attempt_count {
            return Err(ModelError::InvalidRetryMetadata);
        }
        let mut step = Self {
            name: name.into(),
            state,
            attempt_count,
            retry_count,
            result_digest,
            error_digest,
            metadata_digest: Digest::from_text("placeholder"),
        };
        step.metadata_digest = step.compute_digest();
        Ok(step)
    }

    pub fn from_payloads(
        name: impl Into<StepName>,
        state: StepState,
        attempt_count: u16,
        retry_count: u16,
        result_payload: Option<&str>,
        error_payload: Option<&str>,
    ) -> Result<Self, ModelError> {
        Self::new(
            name,
            state,
            attempt_count,
            retry_count,
            digest_payload(result_payload)?,
            digest_payload(error_payload)?,
        )
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&(
            &self.name,
            self.state,
            self.attempt_count,
            self.retry_count,
            &self.result_digest,
            &self.error_digest,
        ))
    }

    pub fn verify_digest(&self) -> bool {
        self.metadata_digest == self.compute_digest()
    }

    pub fn digest(&self) -> Digest {
        self.metadata_digest.clone()
    }
}

fn digest_payload(payload: Option<&str>) -> Result<Option<Digest>, ModelError> {
    payload
        .map(|value| {
            if value.len() > MAX_DIGEST_INPUT_BYTES {
                Err(ModelError::DigestInputTooLarge)
            } else {
                Ok(Digest::from_text(value))
            }
        })
        .transpose()
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionSummary {
    pub id: ExecutionId,
    pub workflow_revision: WorkflowRevisionId,
    pub state: ExecutionState,
    pub timing: ExecutionTiming,
    pub steps: Vec<StepMetadata>,
    pub termination: TerminationMetadata,
    pub result_digest: Option<Digest>,
    pub error_digest: Option<Digest>,
    pub state_error_digest: Option<Digest>,
    pub execution_digest: Digest,
}

impl ExecutionSummary {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<ExecutionId>,
        workflow_revision: impl Into<WorkflowRevisionId>,
        state: ExecutionState,
        timing: ExecutionTiming,
        steps: Vec<StepMetadata>,
        termination: TerminationMetadata,
        result_digest: Option<Digest>,
        error_digest: Option<Digest>,
        state_error_digest: Option<Digest>,
    ) -> Result<Self, ModelError> {
        if steps.len() > MAX_STEPS_PER_EXECUTION
            || steps.iter().any(|step| !step.verify_digest())
            || (state == ExecutionState::Succeeded && error_digest.is_some())
            || (state != ExecutionState::Succeeded && result_digest.is_some())
        {
            return Err(ModelError::InvalidExecutionMetadata);
        }
        let mut execution = Self {
            id: id.into(),
            workflow_revision: workflow_revision.into(),
            state,
            timing,
            steps,
            termination,
            result_digest,
            error_digest,
            state_error_digest,
            execution_digest: Digest::from_text("placeholder"),
        };
        execution.execution_digest = execution.compute_digest();
        Ok(execution)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_payloads(
        id: impl Into<ExecutionId>,
        workflow_revision: impl Into<WorkflowRevisionId>,
        state: ExecutionState,
        timing: ExecutionTiming,
        steps: Vec<StepMetadata>,
        termination: TerminationMetadata,
        result_payload: Option<&str>,
        error_payload: Option<&str>,
        state_error_payload: Option<&str>,
    ) -> Result<Self, ModelError> {
        Self::new(
            id,
            workflow_revision,
            state,
            timing,
            steps,
            termination,
            digest_payload(result_payload)?,
            digest_payload(error_payload)?,
            digest_payload(state_error_payload)?,
        )
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&(
            &self.id,
            &self.workflow_revision,
            self.state,
            &self.timing,
            &self.steps,
            &self.termination,
            &self.result_digest,
            &self.error_digest,
            &self.state_error_digest,
        ))
    }

    pub fn verify_digest(&self) -> bool {
        self.execution_digest == self.compute_digest()
            && self.steps.iter().all(StepMetadata::verify_digest)
    }

    pub fn digest(&self) -> Digest {
        self.execution_digest.clone()
    }

    pub fn matches_scope(&self, scope: &GcpWorkflowsScope) -> bool {
        scope.execution.matches(&self.id)
            && self.workflow_revision == *scope.workflow.workflow_revision()
    }
}

pub type ExecutionMetadata = ExecutionSummary;
pub type ExecutionSnapshot = ExecutionSummary;
pub type WorkflowExecution = ExecutionSummary;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    Complete,
    Partial,
    Unknown,
    AccessLost,
    NotFound,
    Conflict,
    RateLimited,
    Timeout,
    ProviderUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceDigests {
    pub version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub evidence_digest: Digest,
}

impl EvidenceDigests {
    pub fn new(provider_digest: Digest, permission_digest: Digest, scope_digest: Digest) -> Self {
        Self {
            version_digest: Digest::from_text(GCP_WORKFLOWS_EXECUTION_PLUGIN_VERSION_TEXT),
            contract_digest: crate::contract_digest(),
            provider_digest,
            permission_digest,
            scope_digest,
            evidence_digest: Digest::from_text("placeholder"),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpWorkflowsExecutionEvidence {
    pub schema_version: String,
    pub contract_version: String,
    pub plugin_version: String,
    pub state: EvidenceState,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub provider_revision: String,
    pub page_count: u16,
    pub execution_count: u16,
    pub duplicate_execution_count: u16,
    pub executions: Vec<ExecutionSummary>,
    pub record_digests: Vec<Digest>,
    pub cursor_chain_digest: Digest,
    pub failure_digest: Option<Digest>,
    pub native: bool,
    pub connected: bool,
    pub outcome_authority: bool,
    pub work_product_adoption: bool,
    pub digests: EvidenceDigests,
}

impl GcpWorkflowsExecutionEvidence {
    pub fn compute_evidence_digest(&self) -> Digest {
        #[derive(Serialize)]
        struct EvidenceDigestInput<'a> {
            schema_version: &'a str,
            contract_version: &'a str,
            plugin_version: &'a str,
            state: EvidenceState,
            scope_digest: &'a Digest,
            permission_digest: &'a Digest,
            registration_digest: &'a Digest,
            provider_digest: &'a Digest,
            provider_revision: &'a str,
            page_count: u16,
            execution_count: u16,
            duplicate_execution_count: u16,
            executions: &'a [ExecutionSummary],
            record_digests: &'a [Digest],
            cursor_chain_digest: &'a Digest,
            failure_digest: &'a Option<Digest>,
            native: bool,
            connected: bool,
            outcome_authority: bool,
            work_product_adoption: bool,
        }
        Digest::from_serializable(&EvidenceDigestInput {
            schema_version: &self.schema_version,
            contract_version: &self.contract_version,
            plugin_version: &self.plugin_version,
            state: self.state,
            scope_digest: &self.scope_digest,
            permission_digest: &self.permission_digest,
            registration_digest: &self.registration_digest,
            provider_digest: &self.provider_digest,
            provider_revision: &self.provider_revision,
            page_count: self.page_count,
            execution_count: self.execution_count,
            duplicate_execution_count: self.duplicate_execution_count,
            executions: &self.executions,
            record_digests: &self.record_digests,
            cursor_chain_digest: &self.cursor_chain_digest,
            failure_digest: &self.failure_digest,
            native: self.native,
            connected: self.connected,
            outcome_authority: self.outcome_authority,
            work_product_adoption: self.work_product_adoption,
        })
    }

    pub fn verify_digest(&self) -> bool {
        self.schema_version == crate::GCP_WORKFLOWS_EXECUTION_SCHEMA_VERSION
            && self.contract_version == crate::GCP_WORKFLOWS_EXECUTION_CONTRACT_VERSION
            && self.plugin_version == GCP_WORKFLOWS_EXECUTION_PLUGIN_VERSION_TEXT
            && self.provider_revision == crate::GCP_WORKFLOWS_EXECUTION_PROVIDER_REVISION
            && self.page_count <= MAX_PAGES
            && usize::from(self.page_count) == self.record_digests.len()
            && usize::from(self.execution_count) == self.executions.len()
            && self.executions.len() <= MAX_EXECUTIONS
            && !self.native
            && !self.connected
            && !self.outcome_authority
            && !self.work_product_adoption
            && self.digests.version_digest
                == Digest::from_text(GCP_WORKFLOWS_EXECUTION_PLUGIN_VERSION_TEXT)
            && self.digests.contract_digest == crate::contract_digest()
            && self.digests.provider_digest == self.provider_digest
            && self.digests.permission_digest == self.permission_digest
            && self.digests.scope_digest == self.scope_digest
            && self.digests.evidence_digest == self.compute_evidence_digest()
            && self.executions.iter().all(ExecutionSummary::verify_digest)
    }
}

pub type GcpWorkflowsEvidence = GcpWorkflowsExecutionEvidence;
