use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{canonical_digest, sha256_digest};

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: u16 = 32;
pub const MAX_RUNS: usize = 1_000;
pub const MAX_TRACES: usize = 1_000;
pub const MAX_FEEDBACK_SCORES: usize = 5_000;
pub const MAX_ERROR_DIGEST_BYTES: usize = 128;
pub const MAX_EXPERIMENT_RUNS: u32 = 100_000;
pub const MAX_EXAMPLE_COUNT: u64 = 10_000_000;
pub const MAX_TRACE_SPANS: u32 = 1_000;

/// Typed errors for the LangSmith Layer-1 boundary.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum LangSmithEvaluationError {
    #[error("{field} is empty, invalid, or too long")]
    InvalidIdentifier { field: &'static str },
    #[error("the LangSmith API host must be a valid HTTPS origin")]
    InvalidHost,
    #[error("{field} is not a valid bounded revision")]
    InvalidRevision { field: &'static str },
    #[error("{field} is not a lowercase SHA-256 digest")]
    InvalidDigest { field: &'static str },
    #[error("the exact LangSmith evaluation scope is invalid")]
    InvalidScope,
    #[error("the permission snapshot is invalid or over-privileged")]
    InvalidPermissionSnapshot,
    #[error("the registered operation requires permission {permission}")]
    MissingPermission { permission: &'static str },
    #[error("a version, contract digest, provider, permission, and scope registration is required")]
    RegistrationRequired,
    #[error("the LangSmith registration has been revoked")]
    RegistrationRevoked,
    #[error("the LangSmith registration digest is invalid or tampered")]
    RegistrationTampered,
    #[error("the provider manifest is missing or drifted")]
    ProviderManifestDrift,
    #[error("the contract version or digest drifted")]
    ContractDrift,
    #[error("the provider is not bound to the requested exact scope")]
    ScopeMismatch,
    #[error("the project revision drifted")]
    ProjectRevisionDrift,
    #[error("the run is outside the requested exact scope")]
    RunMismatch,
    #[error("the trace is outside the requested exact scope")]
    TraceMismatch,
    #[error("the Mission is outside the requested exact scope")]
    MissionMismatch,
    #[error("the permission revision drifted")]
    PermissionDrift,
    #[error("the dataset revision drifted")]
    DatasetRevisionDrift,
    #[error("the evaluator or evaluator revision does not match the exact scope")]
    EvaluatorMismatch,
    #[error("the experiment or experiment revision does not match the exact scope")]
    ExperimentRevisionDrift,
    #[error("the evaluation request is invalid")]
    InvalidRequest,
    #[error("the requested page size must be between 1 and {maximum}")]
    InvalidPageSize { maximum: u16 },
    #[error("the bounded {field} list exceeded {maximum} items")]
    BoundExceeded { field: &'static str, maximum: usize },
    #[error("the evaluation pagination cursor is invalid for this scope")]
    CursorMismatch,
    #[error("the evaluation pagination cursor repeated")]
    CursorLoop,
    #[error("the evaluation page sequence is invalid")]
    PaginationMismatch,
    #[error("the provider response was partial")]
    PartialData,
    #[error("the evaluation result is stale and cannot claim current evidence")]
    StaleResult,
    #[error("the feedback score must be finite and within [0, 1]")]
    FeedbackScoreOutOfBounds,
    #[error("the bounded evaluation metrics are invalid")]
    InvalidMetrics,
    #[error("the run status or status transition is invalid")]
    InvalidRunStatus,
    #[error("the provider response is invalid or exceeds the bounded contract")]
    InvalidResponse,
    #[error("the provider response fingerprint failed its tamper check")]
    ResponseTampered,
    #[error("the proposal fingerprint failed its tamper check")]
    ProposalTampered,
    #[error("the evidence is not redacted or contains forbidden raw content")]
    RedactionViolation,
    #[error("{field} exceeded the redaction bound of {maximum} bytes")]
    Truncation { field: &'static str, maximum: usize },
    #[error("a provider error occurred: {0}")]
    Provider(LangSmithProviderError),
}

/// Provider failures never retain response bodies or credential material.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum LangSmithProviderError {
    #[error("BLOCKED_ENV: native LangSmith credentials or HTTPS transport are unavailable")]
    BlockedEnv,
    #[error("LangSmith returned HTTP 401")]
    Unauthorized401,
    #[error("LangSmith returned HTTP 403")]
    Forbidden403,
    #[error("LangSmith returned HTTP 404")]
    NotFound404,
    #[error("LangSmith returned HTTP 409 ({reason:?})")]
    Conflict409 { reason: ConflictReason },
    #[error("LangSmith returned HTTP 429")]
    RateLimited429 { retry_after_seconds: Option<u64> },
    #[error("LangSmith request timed out")]
    Timeout,
    #[error("LangSmith returned HTTP {status}")]
    Server5xx { status: u16 },
    #[error("LangSmith access was lost")]
    AccessLoss,
    #[error("the LangSmith registration has been revoked")]
    RegistrationRevoked,
    #[error("LangSmith scope did not match the registered exact scope")]
    ScopeMismatch,
    #[error("LangSmith permission revision drifted")]
    PermissionDrift,
    #[error("LangSmith project revision drifted")]
    ProjectRevisionDrift,
    #[error("LangSmith dataset revision drifted")]
    DatasetRevisionDrift,
    #[error("LangSmith evaluator revision drifted")]
    EvaluatorRevisionDrift,
    #[error("LangSmith experiment revision drifted")]
    ExperimentRevisionDrift,
    #[error("LangSmith response was stale")]
    StaleResult,
    #[error("LangSmith response fingerprint was tampered")]
    ResponseTampered,
    #[error("LangSmith response was invalid or exceeded a bound")]
    InvalidResponse,
    #[error("LangSmith pagination cursor repeated")]
    CursorLoop,
    #[error("mutation operation is outside the Layer-1 provider authority")]
    MutationForbidden,
    #[error("credential resolution failed: {0}")]
    Credential(#[from] CredentialResolutionError),
}

impl LangSmithProviderError {
    #[must_use]
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::Unauthorized401 => Some(401),
            Self::Forbidden403 => Some(403),
            Self::NotFound404 => Some(404),
            Self::Conflict409 { .. } => Some(409),
            Self::RateLimited429 { .. } => Some(429),
            Self::Server5xx { status } => Some(*status),
            Self::BlockedEnv
            | Self::Timeout
            | Self::AccessLoss
            | Self::RegistrationRevoked
            | Self::ScopeMismatch
            | Self::PermissionDrift
            | Self::ProjectRevisionDrift
            | Self::DatasetRevisionDrift
            | Self::EvaluatorRevisionDrift
            | Self::ExperimentRevisionDrift
            | Self::StaleResult
            | Self::ResponseTampered
            | Self::InvalidResponse
            | Self::CursorLoop
            | Self::MutationForbidden
            | Self::Credential(_) => None,
        }
    }

    #[must_use]
    pub const fn is_access_loss(&self) -> bool {
        matches!(
            self,
            Self::Unauthorized401 | Self::Forbidden403 | Self::NotFound404 | Self::AccessLoss
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictReason {
    ScopeDrift,
    PermissionDrift,
    DatasetRevisionDrift,
    EvaluatorRevisionDrift,
    ExperimentRevisionDrift,
    RegistrationRevoked,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CredentialResolutionError {
    #[error("BLOCKED_ENV: native secret resolution is unavailable")]
    BlockedEnv,
    #[error("the opaque secret reference is invalid")]
    InvalidReference,
}

/// A lower-case SHA-256 digest. It is the only content representation emitted
/// for prompt, output, PII, raw error text, and opaque provider bodies.
#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    #[must_use]
    pub fn from_hex(bytes: impl AsRef<[u8]>) -> Self {
        Self(crate::hex_encode(bytes))
    }

    #[must_use]
    pub fn from_text(value: &str) -> Self {
        sha256_digest(value.as_bytes())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self, field: &'static str) -> Result<(), LangSmithEvaluationError> {
        if self.0.len() != 64
            || !self
                .0
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(LangSmithEvaluationError::InvalidDigest { field });
        }
        Ok(())
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Digest").field(&self.0).finish()
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl AsRef<str> for Digest {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl PluginVersion {
    pub const V1: Self = Self {
        major: 1,
        minor: 0,
        patch: 0,
    };

    pub fn parse(value: &str) -> Result<Self, LangSmithEvaluationError> {
        let parts = value.split('.').collect::<Vec<_>>();
        let [major, minor, patch] = parts.as_slice() else {
            return Err(LangSmithEvaluationError::InvalidRevision {
                field: "plugin_version",
            });
        };
        Ok(Self {
            major: major
                .parse()
                .map_err(|_| LangSmithEvaluationError::InvalidRevision {
                    field: "plugin_version",
                })?,
            minor: minor
                .parse()
                .map_err(|_| LangSmithEvaluationError::InvalidRevision {
                    field: "plugin_version",
                })?,
            patch: patch
                .parse()
                .map_err(|_| LangSmithEvaluationError::InvalidRevision {
                    field: "plugin_version",
                })?,
        })
    }
}

impl fmt::Display for PluginVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    ApiKey,
    OAuth,
}

/// An opaque handle to a Layer-2-resolved API key or OAuth credential.
///
/// The supplied handle is immediately digested; neither the handle nor raw
/// secret material is retained, serialized, or shown in debug output.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct SecretReference {
    pub kind: SecretKind,
    pub reference_digest: Digest,
    pub scope_digest: Digest,
    pub revision: Revision,
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("kind", &self.kind)
            .field("reference_digest", &self.reference_digest)
            .field("scope_digest", &self.scope_digest)
            .field("revision", &self.revision)
            .finish()
    }
}

impl SecretReference {
    pub fn new(
        kind: SecretKind,
        opaque_handle: &str,
        scope_digest: Digest,
        revision: Revision,
    ) -> Result<Self, LangSmithEvaluationError> {
        if opaque_handle.trim().is_empty() || opaque_handle.len() > MAX_IDENTIFIER_BYTES {
            return Err(LangSmithEvaluationError::InvalidIdentifier {
                field: "secret_reference",
            });
        }
        scope_digest.validate("scope_digest")?;
        revision.validate("secret_reference_revision")?;
        Ok(Self {
            kind,
            reference_digest: Digest::from_text(opaque_handle),
            scope_digest,
            revision,
        })
    }

    pub fn api_key(
        opaque_handle: &str,
        scope_digest: Digest,
        revision: Revision,
    ) -> Result<Self, LangSmithEvaluationError> {
        Self::new(SecretKind::ApiKey, opaque_handle, scope_digest, revision)
    }

    pub fn oauth(
        opaque_handle: &str,
        scope_digest: Digest,
        revision: Revision,
    ) -> Result<Self, LangSmithEvaluationError> {
        Self::new(SecretKind::OAuth, opaque_handle, scope_digest, revision)
    }

    pub fn with_kind(
        kind: SecretKind,
        opaque_handle: &str,
        scope_digest: Digest,
        revision: Revision,
    ) -> Result<Self, LangSmithEvaluationError> {
        Self::new(kind, opaque_handle, scope_digest, revision)
    }

    pub fn validate(&self) -> Result<(), LangSmithEvaluationError> {
        self.reference_digest.validate("secret_reference_digest")?;
        self.scope_digest.validate("secret_scope_digest")?;
        self.revision.validate("secret_reference_revision")
    }
}

macro_rules! bounded_identifier {
    ($name:ident, $field:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, LangSmithEvaluationError> {
                let value = value.into();
                validate_identifier(&value, $field)?;
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn validate(&self) -> Result<(), LangSmithEvaluationError> {
                Self::new(self.0.clone()).map(|_| ())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

bounded_identifier!(WorkspaceId, "workspace");
bounded_identifier!(ProjectId, "project");
bounded_identifier!(RunId, "run");
bounded_identifier!(TraceId, "trace");
bounded_identifier!(DatasetId, "dataset");
bounded_identifier!(EvaluatorId, "evaluator");
bounded_identifier!(ExperimentId, "experiment");
bounded_identifier!(MissionId, "mission");
bounded_identifier!(ModelId, "model");
bounded_identifier!(WorkProductId, "work_product");
bounded_identifier!(FeedbackId, "feedback");

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Revision(String);

impl Revision {
    pub fn new(value: impl Into<String>) -> Result<Self, LangSmithEvaluationError> {
        let value = value.into();
        validate_revision(&value, "revision")?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn fixture() -> Self {
        Self(String::from("v1"))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self, field: &'static str) -> Result<(), LangSmithEvaluationError> {
        validate_revision(&self.0, field)
    }
}

impl fmt::Display for Revision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct LangSmithHost(String);

impl LangSmithHost {
    pub fn new(value: impl Into<String>) -> Result<Self, LangSmithEvaluationError> {
        let value = value.into();
        validate_host(&value)?;
        Ok(Self(value.trim_end_matches('/').to_ascii_lowercase()))
    }

    #[must_use]
    pub fn fixture() -> Self {
        Self(String::from("https://api.smith.langchain.com"))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LangSmithHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LangSmithPermission {
    ReadRuns,
    ReadTraces,
    ReadDatasets,
    ReadEvaluators,
    ReadFeedback,
    ReadExperiments,
}

impl LangSmithPermission {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ReadRuns => "read_runs",
            Self::ReadTraces => "read_traces",
            Self::ReadDatasets => "read_datasets",
            Self::ReadEvaluators => "read_evaluators",
            Self::ReadFeedback => "read_feedback",
            Self::ReadExperiments => "read_experiments",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LangSmithPermissionSnapshot {
    pub revision: Revision,
    pub permissions: BTreeSet<LangSmithPermission>,
    pub digest: Digest,
}

impl LangSmithPermissionSnapshot {
    pub fn new(
        revision: Revision,
        permissions: impl IntoIterator<Item = LangSmithPermission>,
    ) -> Result<Self, LangSmithEvaluationError> {
        revision.validate("permission_revision")?;
        let permissions = permissions.into_iter().collect::<BTreeSet<_>>();
        if permissions.is_empty() {
            return Err(LangSmithEvaluationError::InvalidPermissionSnapshot);
        }
        let identity = PermissionIdentity {
            revision: revision.clone(),
            permissions: permissions.clone(),
        };
        Ok(Self {
            revision,
            permissions,
            digest: canonical_digest(&identity),
        })
    }

    pub fn read_only(revision: Revision) -> Result<Self, LangSmithEvaluationError> {
        Self::new(
            revision,
            [
                LangSmithPermission::ReadRuns,
                LangSmithPermission::ReadTraces,
                LangSmithPermission::ReadDatasets,
                LangSmithPermission::ReadEvaluators,
                LangSmithPermission::ReadFeedback,
                LangSmithPermission::ReadExperiments,
            ],
        )
    }

    #[must_use]
    pub fn allows(&self, permission: LangSmithPermission) -> bool {
        self.permissions.contains(&permission)
    }

    #[must_use]
    pub fn is_read_only(&self) -> bool {
        true
    }

    pub fn validate(&self) -> Result<(), LangSmithEvaluationError> {
        self.revision.validate("permission_revision")?;
        self.digest.validate("permission_digest")?;
        if self.permissions.is_empty()
            || self.digest
                != canonical_digest(&PermissionIdentity {
                    revision: self.revision.clone(),
                    permissions: self.permissions.clone(),
                })
        {
            return Err(LangSmithEvaluationError::InvalidPermissionSnapshot);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.digest
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct PermissionIdentity {
    revision: Revision,
    permissions: BTreeSet<LangSmithPermission>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LangSmithEvaluationScope {
    pub host: LangSmithHost,
    pub workspace: WorkspaceId,
    pub project: ProjectId,
    pub project_revision: Revision,
    pub run: RunId,
    pub trace: TraceId,
    pub dataset: DatasetId,
    pub dataset_revision: Revision,
    pub evaluator: EvaluatorId,
    pub evaluator_revision: Revision,
    pub experiment: ExperimentId,
    pub experiment_revision: Revision,
    pub mission: MissionId,
    pub mission_revision: Revision,
    pub model_digest: Option<Digest>,
    pub work_product_digest: Option<Digest>,
    pub permission_revision: Revision,
    pub scope_digest: Digest,
}

impl LangSmithEvaluationScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        host: LangSmithHost,
        workspace: WorkspaceId,
        project: ProjectId,
        project_revision: Revision,
        run: RunId,
        trace: TraceId,
        dataset: DatasetId,
        dataset_revision: Revision,
        evaluator: EvaluatorId,
        evaluator_revision: Revision,
        experiment: ExperimentId,
        experiment_revision: Revision,
        mission: MissionId,
        mission_revision: Revision,
        permission_revision: Revision,
    ) -> Result<Self, LangSmithEvaluationError> {
        let mut scope = Self {
            host,
            workspace,
            project,
            project_revision,
            run,
            trace,
            dataset,
            dataset_revision,
            evaluator,
            evaluator_revision,
            experiment,
            experiment_revision,
            mission,
            mission_revision,
            model_digest: None,
            work_product_digest: None,
            permission_revision,
            scope_digest: Digest::from_text("uninitialized-langsmith-scope"),
        };
        scope.recompute_digest()?;
        Ok(scope)
    }

    pub fn fixture(mission: impl Into<String>) -> Result<Self, LangSmithEvaluationError> {
        let mission = MissionId::new(mission)?;
        Self::new(
            LangSmithHost::fixture(),
            WorkspaceId::new("workspace-fixture")?,
            ProjectId::new("project-fixture")?,
            Revision::fixture(),
            RunId::new(format!("run-{}", mission.as_str()))?,
            TraceId::new(format!("trace-{}", mission.as_str()))?,
            DatasetId::new("dataset-fixture")?,
            Revision::fixture(),
            EvaluatorId::new("evaluator-fixture")?,
            Revision::fixture(),
            ExperimentId::new("experiment-fixture")?,
            Revision::fixture(),
            mission,
            Revision::fixture(),
            Revision::fixture(),
        )
    }

    pub fn with_model_digest(mut self, digest: Digest) -> Result<Self, LangSmithEvaluationError> {
        digest.validate("model_digest")?;
        self.model_digest = Some(digest);
        self.recompute_digest()?;
        Ok(self)
    }

    pub fn with_work_product_digest(
        mut self,
        digest: Digest,
    ) -> Result<Self, LangSmithEvaluationError> {
        digest.validate("work_product_digest")?;
        self.work_product_digest = Some(digest);
        self.recompute_digest()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), LangSmithEvaluationError> {
        validate_host(self.host.as_str())?;
        self.workspace.validate()?;
        self.project.validate()?;
        self.project_revision.validate("project_revision")?;
        self.run.validate()?;
        self.trace.validate()?;
        self.dataset.validate()?;
        self.dataset_revision.validate("dataset_revision")?;
        self.evaluator.validate()?;
        self.evaluator_revision.validate("evaluator_revision")?;
        self.experiment.validate()?;
        self.experiment_revision.validate("experiment_revision")?;
        self.mission.validate()?;
        self.mission_revision.validate("mission_revision")?;
        self.permission_revision.validate("permission_revision")?;
        if let Some(digest) = &self.model_digest {
            digest.validate("model_digest")?;
        }
        if let Some(digest) = &self.work_product_digest {
            digest.validate("work_product_digest")?;
        }
        self.scope_digest.validate("scope_digest")?;
        if self.scope_digest != self.calculated_digest() {
            return Err(LangSmithEvaluationError::InvalidScope);
        }
        Ok(())
    }

    #[must_use]
    pub fn digest(&self) -> &Digest {
        &self.scope_digest
    }

    fn calculated_digest(&self) -> Digest {
        canonical_digest(&ScopeIdentity::from(self))
    }

    fn recompute_digest(&mut self) -> Result<(), LangSmithEvaluationError> {
        self.scope_digest = self.calculated_digest();
        self.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ScopeIdentity {
    host: LangSmithHost,
    workspace: WorkspaceId,
    project: ProjectId,
    project_revision: Revision,
    run: RunId,
    trace: TraceId,
    dataset: DatasetId,
    dataset_revision: Revision,
    evaluator: EvaluatorId,
    evaluator_revision: Revision,
    experiment: ExperimentId,
    experiment_revision: Revision,
    mission: MissionId,
    mission_revision: Revision,
    model_digest: Option<Digest>,
    work_product_digest: Option<Digest>,
    permission_revision: Revision,
}

impl From<&LangSmithEvaluationScope> for ScopeIdentity {
    fn from(scope: &LangSmithEvaluationScope) -> Self {
        Self {
            host: scope.host.clone(),
            workspace: scope.workspace.clone(),
            project: scope.project.clone(),
            project_revision: scope.project_revision.clone(),
            run: scope.run.clone(),
            trace: scope.trace.clone(),
            dataset: scope.dataset.clone(),
            dataset_revision: scope.dataset_revision.clone(),
            evaluator: scope.evaluator.clone(),
            evaluator_revision: scope.evaluator_revision.clone(),
            experiment: scope.experiment.clone(),
            experiment_revision: scope.experiment_revision.clone(),
            mission: scope.mission.clone(),
            mission_revision: scope.mission_revision.clone(),
            model_digest: scope.model_digest.clone(),
            work_product_digest: scope.work_product_digest.clone(),
            permission_revision: scope.permission_revision.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LangSmithPluginRegistration {
    pub plugin_version: PluginVersion,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_version: PluginVersion,
    pub scope: LangSmithEvaluationScope,
    pub permission: LangSmithPermissionSnapshot,
    pub active: bool,
    pub registration_digest: Digest,
}

impl LangSmithPluginRegistration {
    pub fn new(
        scope: LangSmithEvaluationScope,
        permission: LangSmithPermissionSnapshot,
    ) -> Result<Self, LangSmithEvaluationError> {
        let mut registration = Self {
            plugin_version: PluginVersion::V1,
            contract_version: String::from(crate::LANGSMITH_EVALUATION_CONTRACT_VERSION),
            contract_digest: Digest::from_text(crate::LANGSMITH_EVALUATION_CONTRACT_DIGEST_INPUT),
            provider_id: String::from(crate::LANGSMITH_EVALUATION_PROVIDER_ID),
            provider_version: PluginVersion::V1,
            scope,
            permission,
            active: true,
            registration_digest: Digest::from_text("uninitialized-langsmith-registration"),
        };
        registration.recompute_digest()?;
        Ok(registration)
    }

    pub fn fixture(scope: LangSmithEvaluationScope) -> Result<Self, LangSmithEvaluationError> {
        let permission = LangSmithPermissionSnapshot::read_only(scope.permission_revision.clone())?;
        Self::new(scope, permission)
    }

    pub fn validate(&self) -> Result<(), LangSmithEvaluationError> {
        self.scope.validate()?;
        self.permission.validate()?;
        if self.contract_version != crate::LANGSMITH_EVALUATION_CONTRACT_VERSION
            || self.contract_digest
                != Digest::from_text(crate::LANGSMITH_EVALUATION_CONTRACT_DIGEST_INPUT)
            || self.provider_id != crate::LANGSMITH_EVALUATION_PROVIDER_ID
        {
            return Err(LangSmithEvaluationError::ContractDrift);
        }
        if self.permission.revision != self.scope.permission_revision {
            return Err(LangSmithEvaluationError::PermissionDrift);
        }
        self.registration_digest.validate("registration_digest")?;
        if self.registration_digest != self.calculated_digest() {
            return Err(LangSmithEvaluationError::RegistrationTampered);
        }
        Ok(())
    }

    pub fn ensure_active(&self) -> Result<(), LangSmithEvaluationError> {
        self.validate()?;
        if self.active {
            Ok(())
        } else {
            Err(LangSmithEvaluationError::RegistrationRevoked)
        }
    }

    #[must_use]
    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }

    pub fn revoke(
        &mut self,
        reason: impl AsRef<str>,
    ) -> Result<RegistrationRevocation, LangSmithEvaluationError> {
        self.validate()?;
        if reason.as_ref().trim().is_empty() {
            return Err(LangSmithEvaluationError::InvalidIdentifier {
                field: "revocation_reason",
            });
        }
        self.active = false;
        self.recompute_digest()?;
        Ok(RegistrationRevocation {
            registration_digest: self.registration_digest.clone(),
            reason_digest: Digest::from_text(reason.as_ref()),
            reversible: true,
        })
    }

    pub fn reissue(
        &self,
        permission: LangSmithPermissionSnapshot,
    ) -> Result<Self, LangSmithEvaluationError> {
        Self::new(self.scope.clone(), permission)
    }

    fn calculated_digest(&self) -> Digest {
        canonical_digest(&RegistrationIdentity {
            plugin_version: self.plugin_version,
            contract_version: self.contract_version.clone(),
            contract_digest: self.contract_digest.clone(),
            provider_id: self.provider_id.clone(),
            provider_version: self.provider_version,
            scope_digest: self.scope.digest().clone(),
            permission_digest: self.permission.digest.clone(),
            active: self.active,
        })
    }

    fn recompute_digest(&mut self) -> Result<(), LangSmithEvaluationError> {
        self.registration_digest = self.calculated_digest();
        self.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct RegistrationIdentity {
    plugin_version: PluginVersion,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    provider_version: PluginVersion,
    scope_digest: Digest,
    permission_digest: Digest,
    active: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegistrationRevocation {
    pub registration_digest: Digest,
    pub reason_digest: Digest,
    pub reversible: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LangSmithEvaluationPolicy {
    pub max_page_size: u16,
    pub max_pages: u16,
    pub max_runs: usize,
    pub max_traces: usize,
    pub max_feedback_scores: usize,
    pub max_age_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LangSmithEvaluationReadRequest {
    pub scope: LangSmithEvaluationScope,
    pub page_size: u16,
    pub cursor: Option<EvaluationCursor>,
    pub as_of_ms: u64,
}

impl LangSmithEvaluationReadRequest {
    pub fn new(
        scope: LangSmithEvaluationScope,
        page_size: u16,
        as_of_ms: u64,
    ) -> Result<Self, LangSmithEvaluationError> {
        if page_size == 0 || page_size > MAX_PAGE_SIZE {
            return Err(LangSmithEvaluationError::InvalidPageSize {
                maximum: MAX_PAGE_SIZE,
            });
        }
        scope.validate()?;
        Ok(Self {
            scope,
            page_size,
            cursor: None,
            as_of_ms,
        })
    }

    pub fn next_page(&self, cursor: EvaluationCursor) -> Result<Self, LangSmithEvaluationError> {
        cursor.validate()?;
        if cursor.scope_digest != *self.scope.digest() {
            return Err(LangSmithEvaluationError::CursorMismatch);
        }
        Ok(Self {
            scope: self.scope.clone(),
            page_size: self.page_size,
            cursor: Some(cursor),
            as_of_ms: self.as_of_ms,
        })
    }

    pub fn validate(
        &self,
        policy: &LangSmithEvaluationPolicy,
    ) -> Result<(), LangSmithEvaluationError> {
        policy.validate()?;
        self.scope.validate()?;
        if self.page_size == 0 || self.page_size > policy.max_page_size {
            return Err(LangSmithEvaluationError::InvalidPageSize {
                maximum: policy.max_page_size,
            });
        }
        if let Some(cursor) = &self.cursor {
            cursor.validate()?;
            if cursor.scope_digest != *self.scope.digest() {
                return Err(LangSmithEvaluationError::CursorMismatch);
            }
        }
        Ok(())
    }
}

impl LangSmithEvaluationPolicy {
    pub fn new(
        max_page_size: u16,
        max_pages: u16,
        max_runs: usize,
        max_traces: usize,
        max_feedback_scores: usize,
        max_age_ms: u64,
    ) -> Result<Self, LangSmithEvaluationError> {
        if max_page_size == 0
            || max_page_size > MAX_PAGE_SIZE
            || max_pages == 0
            || max_pages > MAX_PAGES
        {
            return Err(LangSmithEvaluationError::InvalidRequest);
        }
        if max_runs == 0 || max_runs > MAX_RUNS || max_traces == 0 || max_traces > MAX_TRACES {
            return Err(LangSmithEvaluationError::InvalidRequest);
        }
        if max_feedback_scores == 0 || max_feedback_scores > MAX_FEEDBACK_SCORES {
            return Err(LangSmithEvaluationError::InvalidRequest);
        }
        Ok(Self {
            max_page_size,
            max_pages,
            max_runs,
            max_traces,
            max_feedback_scores,
            max_age_ms,
        })
    }

    #[must_use]
    pub fn fixture() -> Self {
        Self {
            max_page_size: 25,
            max_pages: 8,
            max_runs: 100,
            max_traces: 100,
            max_feedback_scores: 500,
            max_age_ms: 86_400_000,
        }
    }

    pub fn validate(&self) -> Result<(), LangSmithEvaluationError> {
        Self::new(
            self.max_page_size,
            self.max_pages,
            self.max_runs,
            self.max_traces,
            self.max_feedback_scores,
            self.max_age_ms,
        )
        .map(|_| ())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Queued,
    Running,
    Success,
    Error,
    Cancelled,
    Partial,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Present,
    Empty,
    Partial,
    Stale,
    AccessLoss,
    ProviderUnknown,
}

impl EvidenceStatus {
    #[must_use]
    pub const fn is_current_evidence(self) -> bool {
        matches!(self, Self::Present | Self::Empty)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TokenUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: u64,
}

impl TokenUsage {
    pub fn new(
        input_tokens: u64,
        output_tokens: u64,
        total_tokens: u64,
    ) -> Result<Self, LangSmithEvaluationError> {
        if total_tokens < input_tokens.saturating_add(output_tokens) {
            return Err(LangSmithEvaluationError::InvalidMetrics);
        }
        Ok(Self {
            input_tokens,
            output_tokens,
            total_tokens,
        })
    }

    pub fn validate(&self) -> Result<(), LangSmithEvaluationError> {
        if self.total_tokens < self.input_tokens.saturating_add(self.output_tokens) {
            Err(LangSmithEvaluationError::InvalidMetrics)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CostSummary {
    pub amount_micros: u64,
    pub currency: String,
}

impl CostSummary {
    pub fn new(
        amount_micros: u64,
        currency: impl Into<String>,
    ) -> Result<Self, LangSmithEvaluationError> {
        let currency = currency.into().to_ascii_uppercase();
        if currency.len() != 3 || !currency.bytes().all(|byte| byte.is_ascii_uppercase()) {
            return Err(LangSmithEvaluationError::InvalidMetrics);
        }
        Ok(Self {
            amount_micros,
            currency,
        })
    }

    pub fn validate(&self) -> Result<(), LangSmithEvaluationError> {
        Self::new(self.amount_micros, self.currency.clone()).map(|_| ())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LatencySummary {
    pub duration_ms: u64,
}

impl LatencySummary {
    pub fn new(duration_ms: u64) -> Self {
        Self { duration_ms }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RunSummary {
    pub run_id: RunId,
    pub trace_id: TraceId,
    pub project_id: ProjectId,
    pub project_revision: Revision,
    pub model_digest: Option<Digest>,
    pub status: RunStatus,
    pub error_digest: Option<Digest>,
    pub input_digest: Option<Digest>,
    pub output_digest: Option<Digest>,
    pub token_usage: Option<TokenUsage>,
    pub cost: Option<CostSummary>,
    pub latency: Option<LatencySummary>,
    pub summary_digest: Digest,
}

impl RunSummary {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        run_id: RunId,
        trace_id: TraceId,
        project_id: ProjectId,
        project_revision: Revision,
        model_digest: Option<Digest>,
        status: RunStatus,
        error_digest: Option<Digest>,
        input_digest: Option<Digest>,
        output_digest: Option<Digest>,
        token_usage: Option<TokenUsage>,
        cost: Option<CostSummary>,
        latency: Option<LatencySummary>,
    ) -> Result<Self, LangSmithEvaluationError> {
        let mut summary = Self {
            run_id,
            trace_id,
            project_id,
            project_revision,
            model_digest,
            status,
            error_digest,
            input_digest,
            output_digest,
            token_usage,
            cost,
            latency,
            summary_digest: Digest::from_text("uninitialized-run-summary"),
        };
        summary.recompute_digest()?;
        Ok(summary)
    }

    pub fn fixture(scope: &LangSmithEvaluationScope) -> Result<Self, LangSmithEvaluationError> {
        Self::new(
            scope.run.clone(),
            scope.trace.clone(),
            scope.project.clone(),
            scope.project_revision.clone(),
            scope.model_digest.clone(),
            RunStatus::Success,
            None,
            Some(Digest::from_text("fixture-input")),
            Some(Digest::from_text("fixture-output")),
            Some(TokenUsage::new(12, 8, 20)?),
            Some(CostSummary::new(125, "USD")?),
            Some(LatencySummary::new(240)),
        )
    }

    pub fn validate(&self) -> Result<(), LangSmithEvaluationError> {
        self.run_id.validate()?;
        self.trace_id.validate()?;
        self.project_id.validate()?;
        self.project_revision.validate("run_project_revision")?;
        for digest in [
            &self.model_digest,
            &self.error_digest,
            &self.input_digest,
            &self.output_digest,
        ]
        .into_iter()
        .flatten()
        {
            digest.validate("run_content_digest")?;
        }
        if let Some(error) = &self.error_digest
            && error.as_str().len() > MAX_ERROR_DIGEST_BYTES
        {
            return Err(LangSmithEvaluationError::Truncation {
                field: "error_digest",
                maximum: MAX_ERROR_DIGEST_BYTES,
            });
        }
        if let Some(tokens) = &self.token_usage {
            tokens.validate()?;
        }
        if let Some(cost) = &self.cost {
            cost.validate()?;
        }
        self.summary_digest.validate("run_summary_digest")?;
        if self.summary_digest != self.calculated_digest() {
            return Err(LangSmithEvaluationError::ResponseTampered);
        }
        Ok(())
    }

    fn calculated_digest(&self) -> Digest {
        canonical_digest(&RunSummaryIdentity {
            run_id: self.run_id.clone(),
            trace_id: self.trace_id.clone(),
            project_id: self.project_id.clone(),
            project_revision: self.project_revision.clone(),
            model_digest: self.model_digest.clone(),
            status: self.status,
            error_digest: self.error_digest.clone(),
            input_digest: self.input_digest.clone(),
            output_digest: self.output_digest.clone(),
            token_usage: self.token_usage.clone(),
            cost: self.cost.clone(),
            latency: self.latency.clone(),
        })
    }

    fn recompute_digest(&mut self) -> Result<(), LangSmithEvaluationError> {
        if let Some(tokens) = &self.token_usage {
            tokens.validate()?;
        }
        if let Some(cost) = &self.cost {
            cost.validate()?;
        }
        self.summary_digest = self.calculated_digest();
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct RunSummaryIdentity {
    run_id: RunId,
    trace_id: TraceId,
    project_id: ProjectId,
    project_revision: Revision,
    model_digest: Option<Digest>,
    status: RunStatus,
    error_digest: Option<Digest>,
    input_digest: Option<Digest>,
    output_digest: Option<Digest>,
    token_usage: Option<TokenUsage>,
    cost: Option<CostSummary>,
    latency: Option<LatencySummary>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
struct TraceSummaryIdentity {
    trace_id: TraceId,
    root_run_id: RunId,
    project_id: ProjectId,
    project_revision: Revision,
    span_count: u32,
    max_depth: u16,
    status: RunStatus,
    error_count: u32,
    latency: Option<LatencySummary>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TraceSummary {
    pub trace_id: TraceId,
    pub root_run_id: RunId,
    pub project_id: ProjectId,
    pub project_revision: Revision,
    pub span_count: u32,
    pub max_depth: u16,
    pub status: RunStatus,
    pub error_count: u32,
    pub latency: Option<LatencySummary>,
    pub trace_digest: Digest,
}

impl TraceSummary {
    pub fn new(
        trace_id: TraceId,
        root_run_id: RunId,
        project_id: ProjectId,
        project_revision: Revision,
        span_count: u32,
        max_depth: u16,
        status: RunStatus,
        error_count: u32,
        latency: Option<LatencySummary>,
    ) -> Result<Self, LangSmithEvaluationError> {
        if span_count == 0 || span_count > MAX_TRACE_SPANS || max_depth > 256 {
            return Err(LangSmithEvaluationError::BoundExceeded {
                field: "trace_spans_or_depth",
                maximum: MAX_RUNS,
            });
        }
        let mut summary = Self {
            trace_id,
            root_run_id,
            project_id,
            project_revision,
            span_count,
            max_depth,
            status,
            error_count,
            latency,
            trace_digest: Digest::from_text("uninitialized-trace-summary"),
        };
        summary.trace_digest = summary.calculated_digest();
        Ok(summary)
    }

    pub fn fixture(scope: &LangSmithEvaluationScope) -> Result<Self, LangSmithEvaluationError> {
        Self::new(
            scope.trace.clone(),
            scope.run.clone(),
            scope.project.clone(),
            scope.project_revision.clone(),
            3,
            2,
            RunStatus::Success,
            0,
            Some(LatencySummary::new(240)),
        )
    }

    pub fn validate(&self) -> Result<(), LangSmithEvaluationError> {
        self.trace_id.validate()?;
        self.root_run_id.validate()?;
        self.project_id.validate()?;
        self.project_revision.validate("trace_project_revision")?;
        if self.span_count == 0 || self.span_count > MAX_TRACE_SPANS || self.max_depth > 256 {
            return Err(LangSmithEvaluationError::InvalidResponse);
        }
        if self.trace_digest != self.calculated_digest() {
            return Err(LangSmithEvaluationError::ResponseTampered);
        }
        Ok(())
    }

    fn calculated_digest(&self) -> Digest {
        canonical_digest(&TraceSummaryIdentity {
            trace_id: self.trace_id.clone(),
            root_run_id: self.root_run_id.clone(),
            project_id: self.project_id.clone(),
            project_revision: self.project_revision.clone(),
            span_count: self.span_count,
            max_depth: self.max_depth,
            status: self.status,
            error_count: self.error_count,
            latency: self.latency.clone(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ScoreBounds {
    pub minimum: f64,
    pub maximum: f64,
}

impl ScoreBounds {
    pub fn new(minimum: f64, maximum: f64) -> Result<Self, LangSmithEvaluationError> {
        if !minimum.is_finite()
            || !maximum.is_finite()
            || !(0.0..=1.0).contains(&minimum)
            || !(0.0..=1.0).contains(&maximum)
            || minimum > maximum
        {
            return Err(LangSmithEvaluationError::FeedbackScoreOutOfBounds);
        }
        Ok(Self { minimum, maximum })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluatorKind {
    Human,
    Code,
    LlmJudge,
    Pairwise,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DatasetRevisionSummary {
    pub dataset_id: DatasetId,
    pub revision: Revision,
    pub example_count: u64,
    pub schema_digest: Digest,
    pub input_fields_digest: Digest,
    pub output_fields_digest: Digest,
    pub revision_digest: Digest,
}

impl DatasetRevisionSummary {
    pub fn new(
        dataset_id: DatasetId,
        revision: Revision,
        example_count: u64,
        schema_digest: Digest,
        input_fields_digest: Digest,
        output_fields_digest: Digest,
    ) -> Result<Self, LangSmithEvaluationError> {
        if example_count > MAX_EXAMPLE_COUNT {
            return Err(LangSmithEvaluationError::BoundExceeded {
                field: "dataset_examples",
                maximum: usize::try_from(MAX_EXAMPLE_COUNT).unwrap_or(usize::MAX),
            });
        }
        for digest in [&schema_digest, &input_fields_digest, &output_fields_digest] {
            digest.validate("dataset_digest")?;
        }
        revision.validate("dataset_revision")?;
        let mut summary = Self {
            dataset_id,
            revision,
            example_count,
            schema_digest,
            input_fields_digest,
            output_fields_digest,
            revision_digest: Digest::from_text("uninitialized-dataset-revision"),
        };
        summary.revision_digest = summary.calculated_digest();
        Ok(summary)
    }

    pub fn fixture(scope: &LangSmithEvaluationScope) -> Result<Self, LangSmithEvaluationError> {
        Self::new(
            scope.dataset.clone(),
            scope.dataset_revision.clone(),
            12,
            Digest::from_text("fixture-dataset-schema"),
            Digest::from_text("fixture-dataset-input-fields"),
            Digest::from_text("fixture-dataset-output-fields"),
        )
    }

    pub fn validate(&self) -> Result<(), LangSmithEvaluationError> {
        self.dataset_id.validate()?;
        self.revision.validate("dataset_revision")?;
        if self.example_count > MAX_EXAMPLE_COUNT {
            return Err(LangSmithEvaluationError::InvalidResponse);
        }
        for digest in [
            &self.schema_digest,
            &self.input_fields_digest,
            &self.output_fields_digest,
        ] {
            digest.validate("dataset_digest")?;
        }
        self.revision_digest.validate("dataset_revision_digest")?;
        if self.revision_digest != self.calculated_digest() {
            return Err(LangSmithEvaluationError::ResponseTampered);
        }
        Ok(())
    }

    fn calculated_digest(&self) -> Digest {
        canonical_digest(&DatasetRevisionIdentity {
            dataset_id: self.dataset_id.clone(),
            revision: self.revision.clone(),
            example_count: self.example_count,
            schema_digest: self.schema_digest.clone(),
            input_fields_digest: self.input_fields_digest.clone(),
            output_fields_digest: self.output_fields_digest.clone(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct DatasetRevisionIdentity {
    dataset_id: DatasetId,
    revision: Revision,
    example_count: u64,
    schema_digest: Digest,
    input_fields_digest: Digest,
    output_fields_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct EvaluatorRevisionSummary {
    pub evaluator_id: EvaluatorId,
    pub revision: Revision,
    pub kind: EvaluatorKind,
    pub score_bounds: ScoreBounds,
    pub criteria_digest: Digest,
    pub revision_digest: Digest,
}

impl EvaluatorRevisionSummary {
    pub fn new(
        evaluator_id: EvaluatorId,
        revision: Revision,
        kind: EvaluatorKind,
        score_bounds: ScoreBounds,
        criteria_digest: Digest,
    ) -> Result<Self, LangSmithEvaluationError> {
        revision.validate("evaluator_revision")?;
        criteria_digest.validate("evaluator_criteria_digest")?;
        let mut summary = Self {
            evaluator_id,
            revision,
            kind,
            score_bounds,
            criteria_digest,
            revision_digest: Digest::from_text("uninitialized-evaluator-revision"),
        };
        summary.revision_digest = summary.calculated_digest();
        Ok(summary)
    }

    pub fn fixture(scope: &LangSmithEvaluationScope) -> Result<Self, LangSmithEvaluationError> {
        Self::new(
            scope.evaluator.clone(),
            scope.evaluator_revision.clone(),
            EvaluatorKind::Code,
            ScoreBounds::new(0.0, 1.0)?,
            Digest::from_text("fixture-evaluator-criteria"),
        )
    }

    pub fn validate(&self) -> Result<(), LangSmithEvaluationError> {
        self.evaluator_id.validate()?;
        self.revision.validate("evaluator_revision")?;
        let _ = ScoreBounds::new(self.score_bounds.minimum, self.score_bounds.maximum)?;
        self.criteria_digest.validate("evaluator_criteria_digest")?;
        self.revision_digest.validate("evaluator_revision_digest")?;
        if self.revision_digest != self.calculated_digest() {
            return Err(LangSmithEvaluationError::ResponseTampered);
        }
        Ok(())
    }

    fn calculated_digest(&self) -> Digest {
        canonical_digest(&EvaluatorRevisionIdentity {
            evaluator_id: self.evaluator_id.clone(),
            revision: self.revision.clone(),
            kind: self.kind,
            score_bounds: self.score_bounds.clone(),
            criteria_digest: self.criteria_digest.clone(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
struct EvaluatorRevisionIdentity {
    evaluator_id: EvaluatorId,
    revision: Revision,
    kind: EvaluatorKind,
    score_bounds: ScoreBounds,
    criteria_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct FeedbackScore {
    pub feedback_id_digest: Digest,
    pub run_id: RunId,
    pub trace_id: TraceId,
    pub evaluator_id: EvaluatorId,
    pub evaluator_revision: Revision,
    pub score: f64,
    pub score_digest: Digest,
}

impl FeedbackScore {
    #[allow(clippy::needless_pass_by_value)]
    pub fn new(
        feedback_id: FeedbackId,
        run_id: RunId,
        trace_id: TraceId,
        evaluator_id: EvaluatorId,
        evaluator_revision: Revision,
        score: f64,
    ) -> Result<Self, LangSmithEvaluationError> {
        if !score.is_finite() || !(0.0..=1.0).contains(&score) {
            return Err(LangSmithEvaluationError::FeedbackScoreOutOfBounds);
        }
        evaluator_revision.validate("feedback_evaluator_revision")?;
        let feedback_id_digest = Digest::from_text(feedback_id.as_str());
        let mut feedback = Self {
            feedback_id_digest,
            run_id,
            trace_id,
            evaluator_id,
            evaluator_revision,
            score,
            score_digest: Digest::from_text("uninitialized-feedback-score"),
        };
        feedback.score_digest = feedback.calculated_digest();
        Ok(feedback)
    }

    pub fn fixture(scope: &LangSmithEvaluationScope) -> Result<Self, LangSmithEvaluationError> {
        Self::new(
            FeedbackId::new("feedback-fixture")?,
            scope.run.clone(),
            scope.trace.clone(),
            scope.evaluator.clone(),
            scope.evaluator_revision.clone(),
            0.87,
        )
    }

    pub fn validate(&self) -> Result<(), LangSmithEvaluationError> {
        self.feedback_id_digest.validate("feedback_id_digest")?;
        self.run_id.validate()?;
        self.trace_id.validate()?;
        self.evaluator_id.validate()?;
        self.evaluator_revision
            .validate("feedback_evaluator_revision")?;
        if !self.score.is_finite() || !(0.0..=1.0).contains(&self.score) {
            return Err(LangSmithEvaluationError::FeedbackScoreOutOfBounds);
        }
        self.score_digest.validate("feedback_score_digest")?;
        if self.score_digest != self.calculated_digest() {
            return Err(LangSmithEvaluationError::ResponseTampered);
        }
        Ok(())
    }

    fn calculated_digest(&self) -> Digest {
        canonical_digest(&FeedbackScoreIdentity {
            feedback_id_digest: self.feedback_id_digest.clone(),
            run_id: self.run_id.clone(),
            trace_id: self.trace_id.clone(),
            evaluator_id: self.evaluator_id.clone(),
            evaluator_revision: self.evaluator_revision.clone(),
            score_bits: self.score.to_bits(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct FeedbackScoreIdentity {
    feedback_id_digest: Digest,
    run_id: RunId,
    trace_id: TraceId,
    evaluator_id: EvaluatorId,
    evaluator_revision: Revision,
    score_bits: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ExperimentEvidence {
    pub experiment_id: ExperimentId,
    pub experiment_revision: Revision,
    pub dataset_id: DatasetId,
    pub dataset_revision: Revision,
    pub evaluator_id: EvaluatorId,
    pub evaluator_revision: Revision,
    pub run_count: u32,
    pub completed_count: u32,
    pub mean_score: Option<f64>,
    pub cost: Option<CostSummary>,
    pub latency: Option<LatencySummary>,
    pub experiment_digest: Digest,
}

impl ExperimentEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        experiment_id: ExperimentId,
        experiment_revision: Revision,
        dataset_id: DatasetId,
        dataset_revision: Revision,
        evaluator_id: EvaluatorId,
        evaluator_revision: Revision,
        run_count: u32,
        completed_count: u32,
        mean_score: Option<f64>,
        cost: Option<CostSummary>,
        latency: Option<LatencySummary>,
    ) -> Result<Self, LangSmithEvaluationError> {
        if run_count > MAX_EXPERIMENT_RUNS || completed_count > run_count {
            return Err(LangSmithEvaluationError::InvalidMetrics);
        }
        if let Some(score) = mean_score
            && (!score.is_finite() || !(0.0..=1.0).contains(&score))
        {
            return Err(LangSmithEvaluationError::FeedbackScoreOutOfBounds);
        }
        if let Some(cost) = &cost {
            cost.validate()?;
        }
        let mut evidence = Self {
            experiment_id,
            experiment_revision,
            dataset_id,
            dataset_revision,
            evaluator_id,
            evaluator_revision,
            run_count,
            completed_count,
            mean_score,
            cost,
            latency,
            experiment_digest: Digest::from_text("uninitialized-experiment"),
        };
        evidence.experiment_digest = evidence.calculated_digest();
        Ok(evidence)
    }

    pub fn fixture(scope: &LangSmithEvaluationScope) -> Result<Self, LangSmithEvaluationError> {
        Self::new(
            scope.experiment.clone(),
            scope.experiment_revision.clone(),
            scope.dataset.clone(),
            scope.dataset_revision.clone(),
            scope.evaluator.clone(),
            scope.evaluator_revision.clone(),
            1,
            1,
            Some(0.87),
            Some(CostSummary::new(125, "USD")?),
            Some(LatencySummary::new(240)),
        )
    }

    pub fn validate(&self) -> Result<(), LangSmithEvaluationError> {
        self.experiment_id.validate()?;
        self.experiment_revision.validate("experiment_revision")?;
        self.dataset_id.validate()?;
        self.dataset_revision
            .validate("experiment_dataset_revision")?;
        self.evaluator_id.validate()?;
        self.evaluator_revision
            .validate("experiment_evaluator_revision")?;
        if self.run_count > MAX_EXPERIMENT_RUNS || self.completed_count > self.run_count {
            return Err(LangSmithEvaluationError::InvalidMetrics);
        }
        if let Some(score) = self.mean_score
            && (!score.is_finite() || !(0.0..=1.0).contains(&score))
        {
            return Err(LangSmithEvaluationError::FeedbackScoreOutOfBounds);
        }
        if let Some(cost) = &self.cost {
            cost.validate()?;
        }
        self.experiment_digest.validate("experiment_digest")?;
        if self.experiment_digest != self.calculated_digest() {
            return Err(LangSmithEvaluationError::ResponseTampered);
        }
        Ok(())
    }

    fn calculated_digest(&self) -> Digest {
        canonical_digest(&ExperimentIdentity {
            experiment_id: self.experiment_id.clone(),
            experiment_revision: self.experiment_revision.clone(),
            dataset_id: self.dataset_id.clone(),
            dataset_revision: self.dataset_revision.clone(),
            evaluator_id: self.evaluator_id.clone(),
            evaluator_revision: self.evaluator_revision.clone(),
            run_count: self.run_count,
            completed_count: self.completed_count,
            mean_score_bits: self.mean_score.map(f64::to_bits),
            cost: self.cost.clone(),
            latency: self.latency.clone(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
struct ExperimentIdentity {
    experiment_id: ExperimentId,
    experiment_revision: Revision,
    dataset_id: DatasetId,
    dataset_revision: Revision,
    evaluator_id: EvaluatorId,
    evaluator_revision: Revision,
    run_count: u32,
    completed_count: u32,
    mean_score_bits: Option<u64>,
    cost: Option<CostSummary>,
    latency: Option<LatencySummary>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ExperimentComparisonEvidence {
    pub baseline_experiment: ExperimentId,
    pub candidate_experiment: ExperimentId,
    pub baseline_revision: Revision,
    pub candidate_revision: Revision,
    pub dataset_revision: Revision,
    pub evaluator_revision: Revision,
    pub score_delta: Option<f64>,
    pub cost_delta_micros: Option<i64>,
    pub latency_delta_ms: Option<i64>,
    pub comparison_digest: Digest,
}

impl ExperimentComparisonEvidence {
    pub fn new(
        baseline_experiment: ExperimentId,
        candidate_experiment: ExperimentId,
        baseline_revision: Revision,
        candidate_revision: Revision,
        dataset_revision: Revision,
        evaluator_revision: Revision,
        score_delta: Option<f64>,
        cost_delta_micros: Option<i64>,
        latency_delta_ms: Option<i64>,
    ) -> Result<Self, LangSmithEvaluationError> {
        if let Some(score_delta) = score_delta
            && (!score_delta.is_finite() || !(-1.0..=1.0).contains(&score_delta))
        {
            return Err(LangSmithEvaluationError::FeedbackScoreOutOfBounds);
        }
        let mut comparison = Self {
            baseline_experiment,
            candidate_experiment,
            baseline_revision,
            candidate_revision,
            dataset_revision,
            evaluator_revision,
            score_delta,
            cost_delta_micros,
            latency_delta_ms,
            comparison_digest: Digest::from_text("uninitialized-comparison"),
        };
        comparison.comparison_digest = comparison.calculated_digest();
        Ok(comparison)
    }

    pub fn validate(&self) -> Result<(), LangSmithEvaluationError> {
        self.baseline_experiment.validate()?;
        self.candidate_experiment.validate()?;
        self.baseline_revision
            .validate("baseline_experiment_revision")?;
        self.candidate_revision
            .validate("candidate_experiment_revision")?;
        self.dataset_revision
            .validate("comparison_dataset_revision")?;
        self.evaluator_revision
            .validate("comparison_evaluator_revision")?;
        if let Some(score_delta) = self.score_delta
            && (!score_delta.is_finite() || !(-1.0..=1.0).contains(&score_delta))
        {
            return Err(LangSmithEvaluationError::FeedbackScoreOutOfBounds);
        }
        self.comparison_digest.validate("comparison_digest")?;
        if self.comparison_digest != self.calculated_digest() {
            return Err(LangSmithEvaluationError::ResponseTampered);
        }
        Ok(())
    }

    fn calculated_digest(&self) -> Digest {
        canonical_digest(&ComparisonIdentity {
            baseline_experiment: self.baseline_experiment.clone(),
            candidate_experiment: self.candidate_experiment.clone(),
            baseline_revision: self.baseline_revision.clone(),
            candidate_revision: self.candidate_revision.clone(),
            dataset_revision: self.dataset_revision.clone(),
            evaluator_revision: self.evaluator_revision.clone(),
            score_delta_bits: self.score_delta.map(f64::to_bits),
            cost_delta_micros: self.cost_delta_micros,
            latency_delta_ms: self.latency_delta_ms,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ComparisonIdentity {
    baseline_experiment: ExperimentId,
    candidate_experiment: ExperimentId,
    baseline_revision: Revision,
    candidate_revision: Revision,
    dataset_revision: Revision,
    evaluator_revision: Revision,
    score_delta_bits: Option<u64>,
    cost_delta_micros: Option<i64>,
    latency_delta_ms: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvaluationCursor {
    pub page: u16,
    pub scope_digest: Digest,
    pub previous_page_digest: Digest,
    pub cursor_digest: Digest,
}

impl EvaluationCursor {
    pub fn new(
        page: u16,
        scope_digest: Digest,
        previous_page_digest: Digest,
    ) -> Result<Self, LangSmithEvaluationError> {
        if page == 0 {
            return Err(LangSmithEvaluationError::InvalidRequest);
        }
        scope_digest.validate("cursor_scope_digest")?;
        previous_page_digest.validate("cursor_page_digest")?;
        let mut cursor = Self {
            page,
            scope_digest,
            previous_page_digest,
            cursor_digest: Digest::from_text("uninitialized-cursor"),
        };
        cursor.cursor_digest = canonical_digest(&CursorIdentity {
            page,
            scope_digest: cursor.scope_digest.clone(),
            previous_page_digest: cursor.previous_page_digest.clone(),
        });
        Ok(cursor)
    }

    pub fn validate(&self) -> Result<(), LangSmithEvaluationError> {
        if self.page == 0 {
            return Err(LangSmithEvaluationError::InvalidRequest);
        }
        self.scope_digest.validate("cursor_scope_digest")?;
        self.previous_page_digest.validate("cursor_page_digest")?;
        self.cursor_digest.validate("cursor_digest")?;
        let expected = canonical_digest(&CursorIdentity {
            page: self.page,
            scope_digest: self.scope_digest.clone(),
            previous_page_digest: self.previous_page_digest.clone(),
        });
        if self.cursor_digest != expected {
            return Err(LangSmithEvaluationError::ResponseTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct CursorIdentity {
    page: u16,
    scope_digest: Digest,
    previous_page_digest: Digest,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct LangSmithEvaluationPage {
    pub scope_digest: Digest,
    pub page: u16,
    pub runs: Vec<RunSummary>,
    pub traces: Vec<TraceSummary>,
    pub dataset: DatasetRevisionSummary,
    pub evaluator: EvaluatorRevisionSummary,
    pub feedback: Vec<FeedbackScore>,
    pub experiment: ExperimentEvidence,
    pub comparison: Option<ExperimentComparisonEvidence>,
    pub status: EvidenceStatus,
    pub partial: bool,
    pub next_cursor: Option<EvaluationCursor>,
    pub observed_at_ms: u64,
    pub response_digest: Digest,
    pub reported_response_digest: Option<Digest>,
}

impl LangSmithEvaluationPage {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope_digest: Digest,
        page: u16,
        runs: Vec<RunSummary>,
        traces: Vec<TraceSummary>,
        dataset: DatasetRevisionSummary,
        evaluator: EvaluatorRevisionSummary,
        feedback: Vec<FeedbackScore>,
        experiment: ExperimentEvidence,
        comparison: Option<ExperimentComparisonEvidence>,
        status: EvidenceStatus,
        partial: bool,
        next_cursor: Option<EvaluationCursor>,
        observed_at_ms: u64,
    ) -> Result<Self, LangSmithEvaluationError> {
        if page == 0 {
            return Err(LangSmithEvaluationError::InvalidRequest);
        }
        let mut response = Self {
            scope_digest,
            page,
            runs,
            traces,
            dataset,
            evaluator,
            feedback,
            experiment,
            comparison,
            status,
            partial,
            next_cursor,
            observed_at_ms,
            response_digest: Digest::from_text("uninitialized-page"),
            reported_response_digest: None,
        };
        response.response_digest = response.calculated_digest();
        Ok(response)
    }

    pub fn fixture(scope: &LangSmithEvaluationScope) -> Result<Self, LangSmithEvaluationError> {
        let run = RunSummary::fixture(scope)?;
        let trace = TraceSummary::fixture(scope)?;
        let dataset = DatasetRevisionSummary::fixture(scope)?;
        let evaluator = EvaluatorRevisionSummary::fixture(scope)?;
        let feedback = vec![FeedbackScore::fixture(scope)?];
        let experiment = ExperimentEvidence::fixture(scope)?;
        Self::new(
            scope.digest().clone(),
            1,
            vec![run],
            vec![trace],
            dataset,
            evaluator,
            feedback,
            experiment,
            None,
            EvidenceStatus::Present,
            false,
            None,
            1_000,
        )
    }

    pub fn with_next_cursor(
        mut self,
        cursor: Option<EvaluationCursor>,
    ) -> Result<Self, LangSmithEvaluationError> {
        self.next_cursor = cursor;
        self.response_digest = self.calculated_digest();
        Ok(self)
    }

    pub fn validate(
        &self,
        policy: &LangSmithEvaluationPolicy,
    ) -> Result<(), LangSmithEvaluationError> {
        policy.validate()?;
        self.scope_digest.validate("page_scope_digest")?;
        if self.page == 0 || self.runs.len() > policy.max_page_size as usize {
            return Err(LangSmithEvaluationError::InvalidResponse);
        }
        if self.runs.len() > policy.max_runs {
            return Err(LangSmithEvaluationError::BoundExceeded {
                field: "runs",
                maximum: policy.max_runs,
            });
        }
        if self.traces.len() > policy.max_traces {
            return Err(LangSmithEvaluationError::BoundExceeded {
                field: "traces",
                maximum: policy.max_traces,
            });
        }
        if self.feedback.len() > policy.max_feedback_scores {
            return Err(LangSmithEvaluationError::BoundExceeded {
                field: "feedback",
                maximum: policy.max_feedback_scores,
            });
        }
        for run in &self.runs {
            run.validate()?;
        }
        for trace in &self.traces {
            trace.validate()?;
        }
        self.dataset.validate()?;
        self.evaluator.validate()?;
        for feedback in &self.feedback {
            feedback.validate()?;
        }
        self.experiment.validate()?;
        if let Some(comparison) = &self.comparison {
            comparison.validate()?;
        }
        if let Some(cursor) = &self.next_cursor {
            cursor.validate()?;
            if cursor.page != self.page.saturating_add(1)
                || cursor.scope_digest != self.scope_digest
                || cursor.previous_page_digest != self.response_digest
            {
                return Err(LangSmithEvaluationError::PaginationMismatch);
            }
        }
        self.response_digest.validate("response_digest")?;
        if self.response_digest != self.calculated_digest()
            || self
                .reported_response_digest
                .as_ref()
                .is_some_and(|reported| reported != &self.response_digest)
        {
            return Err(LangSmithEvaluationError::ResponseTampered);
        }
        if self.partial && self.status != EvidenceStatus::Partial {
            return Err(LangSmithEvaluationError::InvalidResponse);
        }
        Ok(())
    }

    #[must_use]
    pub fn is_current_evidence(&self) -> bool {
        self.status.is_current_evidence() && !self.partial
    }

    fn calculated_digest(&self) -> Digest {
        canonical_digest(&PageIdentity {
            scope_digest: self.scope_digest.clone(),
            page: self.page,
            runs: self.runs.clone(),
            traces: self.traces.clone(),
            dataset: self.dataset.clone(),
            evaluator: self.evaluator.clone(),
            feedback: self.feedback.clone(),
            experiment: self.experiment.clone(),
            comparison: self.comparison.clone(),
            status: self.status,
            partial: self.partial,
            observed_at_ms: self.observed_at_ms,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
struct PageIdentity {
    scope_digest: Digest,
    page: u16,
    runs: Vec<RunSummary>,
    traces: Vec<TraceSummary>,
    dataset: DatasetRevisionSummary,
    evaluator: EvaluatorRevisionSummary,
    feedback: Vec<FeedbackScore>,
    experiment: ExperimentEvidence,
    comparison: Option<ExperimentComparisonEvidence>,
    status: EvidenceStatus,
    partial: bool,
    observed_at_ms: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct LangSmithEvaluationEvidence {
    pub scope: LangSmithEvaluationScope,
    pub page_count: u16,
    pub runs: Vec<RunSummary>,
    pub traces: Vec<TraceSummary>,
    pub dataset: DatasetRevisionSummary,
    pub evaluator: EvaluatorRevisionSummary,
    pub feedback: Vec<FeedbackScore>,
    pub experiment: ExperimentEvidence,
    pub comparison: Option<ExperimentComparisonEvidence>,
    pub status: EvidenceStatus,
    pub partial: bool,
    pub stale: bool,
    pub evidence_digest: Digest,
}

impl LangSmithEvaluationEvidence {
    pub fn validate(
        &self,
        policy: &LangSmithEvaluationPolicy,
    ) -> Result<(), LangSmithEvaluationError> {
        self.scope.validate()?;
        if self.page_count == 0 || self.page_count > policy.max_pages {
            return Err(LangSmithEvaluationError::InvalidResponse);
        }
        if self.runs.len() > policy.max_runs
            || self.traces.len() > policy.max_traces
            || self.feedback.len() > policy.max_feedback_scores
        {
            return Err(LangSmithEvaluationError::InvalidResponse);
        }
        for run in &self.runs {
            run.validate()?;
        }
        for trace in &self.traces {
            trace.validate()?;
        }
        self.dataset.validate()?;
        self.evaluator.validate()?;
        for feedback in &self.feedback {
            feedback.validate()?;
        }
        self.experiment.validate()?;
        if let Some(comparison) = &self.comparison {
            comparison.validate()?;
        }
        self.evidence_digest.validate("evidence_digest")?;
        if self.evidence_digest != self.calculated_digest() {
            return Err(LangSmithEvaluationError::ResponseTampered);
        }
        if self.partial != matches!(self.status, EvidenceStatus::Partial) {
            return Err(LangSmithEvaluationError::InvalidResponse);
        }
        if self.stale != matches!(self.status, EvidenceStatus::Stale) {
            return Err(LangSmithEvaluationError::InvalidResponse);
        }
        Ok(())
    }

    #[must_use]
    pub fn is_current(&self) -> bool {
        !self.stale && self.status.is_current_evidence() && !self.partial
    }

    fn calculated_digest(&self) -> Digest {
        canonical_digest(&EvidenceIdentity {
            scope: self.scope.clone(),
            page_count: self.page_count,
            runs: self.runs.clone(),
            traces: self.traces.clone(),
            dataset: self.dataset.clone(),
            evaluator: self.evaluator.clone(),
            feedback: self.feedback.clone(),
            experiment: self.experiment.clone(),
            comparison: self.comparison.clone(),
            status: self.status,
            partial: self.partial,
            stale: self.stale,
        })
    }

    pub(crate) fn from_pages(
        scope: LangSmithEvaluationScope,
        pages: &[LangSmithEvaluationPage],
        status: EvidenceStatus,
        stale: bool,
    ) -> Result<Self, LangSmithEvaluationError> {
        let Some(first) = pages.first() else {
            return Err(LangSmithEvaluationError::InvalidResponse);
        };
        let mut runs = Vec::new();
        let mut traces = Vec::new();
        let mut feedback = Vec::new();
        for page in pages {
            runs.extend(page.runs.clone());
            traces.extend(page.traces.clone());
            feedback.extend(page.feedback.clone());
        }
        let mut evidence = Self {
            scope,
            page_count: u16::try_from(pages.len())
                .map_err(|_| LangSmithEvaluationError::InvalidResponse)?,
            runs,
            traces,
            dataset: first.dataset.clone(),
            evaluator: first.evaluator.clone(),
            feedback,
            experiment: first.experiment.clone(),
            comparison: first.comparison.clone(),
            status,
            partial: matches!(status, EvidenceStatus::Partial),
            stale,
            evidence_digest: Digest::from_text("uninitialized-evidence"),
        };
        evidence.evidence_digest = evidence.calculated_digest();
        Ok(evidence)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
struct EvidenceIdentity {
    scope: LangSmithEvaluationScope,
    page_count: u16,
    runs: Vec<RunSummary>,
    traces: Vec<TraceSummary>,
    dataset: DatasetRevisionSummary,
    evaluator: EvaluatorRevisionSummary,
    feedback: Vec<FeedbackScore>,
    experiment: ExperimentEvidence,
    comparison: Option<ExperimentComparisonEvidence>,
    status: EvidenceStatus,
    partial: bool,
    stale: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct EvaluationResultProposal {
    pub scope: LangSmithEvaluationScope,
    pub plugin_version: PluginVersion,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_manifest_digest: Digest,
    pub registration_digest: Digest,
    pub evidence: LangSmithEvaluationEvidence,
    pub proposed_at_ms: u64,
    pub adopted: bool,
    pub durable_native_receipt: bool,
    pub kernel_verified: bool,
    pub connected: bool,
    pub native: bool,
    pub can_claim_current: bool,
    pub proposal_digest: Digest,
}

impl EvaluationResultProposal {
    pub(crate) fn new(
        registration: &LangSmithPluginRegistration,
        provider_manifest_digest: Digest,
        evidence: LangSmithEvaluationEvidence,
        proposed_at_ms: u64,
    ) -> Self {
        let mut proposal = Self {
            scope: registration.scope.clone(),
            plugin_version: registration.plugin_version,
            contract_version: registration.contract_version.clone(),
            contract_digest: registration.contract_digest.clone(),
            provider_manifest_digest,
            registration_digest: registration.registration_digest.clone(),
            evidence,
            proposed_at_ms,
            adopted: false,
            durable_native_receipt: false,
            kernel_verified: false,
            connected: false,
            native: false,
            can_claim_current: false,
            proposal_digest: Digest::from_text("uninitialized-proposal"),
        };
        proposal.can_claim_current = proposal.evidence.is_current();
        proposal.proposal_digest = proposal.calculated_digest();
        proposal
    }

    pub fn validate(
        &self,
        registration: &LangSmithPluginRegistration,
        policy: &LangSmithEvaluationPolicy,
    ) -> Result<(), LangSmithEvaluationError> {
        registration.ensure_active()?;
        self.evidence.validate(policy)?;
        self.scope.validate()?;
        if self.scope.digest() != registration.scope.digest()
            || self.registration_digest != registration.registration_digest
            || self.contract_version != crate::LANGSMITH_EVALUATION_CONTRACT_VERSION
            || self.contract_digest != registration.contract_digest
            || self.connected
            || self.native
            || self.adopted
            || self.durable_native_receipt
            || self.kernel_verified
            || self.can_claim_current != self.evidence.is_current()
        {
            return Err(LangSmithEvaluationError::ProposalTampered);
        }
        self.provider_manifest_digest
            .validate("provider_manifest_digest")?;
        self.registration_digest.validate("registration_digest")?;
        self.contract_digest.validate("contract_digest")?;
        self.proposal_digest.validate("proposal_digest")?;
        if self.proposal_digest != self.calculated_digest() {
            return Err(LangSmithEvaluationError::ProposalTampered);
        }
        Ok(())
    }

    #[must_use]
    pub fn is_redacted(&self) -> bool {
        !self.adopted && !self.native && !self.connected
    }

    fn calculated_digest(&self) -> Digest {
        canonical_digest(&ProposalIdentity {
            scope: self.scope.clone(),
            plugin_version: self.plugin_version,
            contract_version: self.contract_version.clone(),
            contract_digest: self.contract_digest.clone(),
            provider_manifest_digest: self.provider_manifest_digest.clone(),
            registration_digest: self.registration_digest.clone(),
            evidence: self.evidence.clone(),
            proposed_at_ms: self.proposed_at_ms,
            adopted: self.adopted,
            durable_native_receipt: self.durable_native_receipt,
            kernel_verified: self.kernel_verified,
            connected: self.connected,
            native: self.native,
            can_claim_current: self.can_claim_current,
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
struct ProposalIdentity {
    scope: LangSmithEvaluationScope,
    plugin_version: PluginVersion,
    contract_version: String,
    contract_digest: Digest,
    provider_manifest_digest: Digest,
    registration_digest: Digest,
    evidence: LangSmithEvaluationEvidence,
    proposed_at_ms: u64,
    adopted: bool,
    durable_native_receipt: bool,
    kernel_verified: bool,
    connected: bool,
    native: bool,
    can_claim_current: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvaluationReceiptCandidate {
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub durable: bool,
    pub kernel_verified: bool,
    pub external_write_performed: bool,
    pub native: bool,
    pub connected: bool,
    pub receipt_digest: Digest,
}

impl EvaluationReceiptCandidate {
    pub(crate) fn from_proposal(proposal: &EvaluationResultProposal) -> Self {
        let mut candidate = Self {
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.scope.digest().clone(),
            registration_digest: proposal.registration_digest.clone(),
            durable: false,
            kernel_verified: false,
            external_write_performed: false,
            native: false,
            connected: false,
            receipt_digest: Digest::from_text("uninitialized-receipt-candidate"),
        };
        candidate.receipt_digest = canonical_digest(&ReceiptIdentity {
            proposal_digest: candidate.proposal_digest.clone(),
            scope_digest: candidate.scope_digest.clone(),
            registration_digest: candidate.registration_digest.clone(),
            durable: candidate.durable,
            kernel_verified: candidate.kernel_verified,
            external_write_performed: candidate.external_write_performed,
            native: candidate.native,
            connected: candidate.connected,
        });
        candidate
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ReceiptIdentity {
    proposal_digest: Digest,
    scope_digest: Digest,
    registration_digest: Digest,
    durable: bool,
    kernel_verified: bool,
    external_write_performed: bool,
    native: bool,
    connected: bool,
}

fn validate_identifier(value: &str, field: &'static str) -> Result<(), LangSmithEvaluationError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:@/+~-".contains(&byte))
    {
        return Err(LangSmithEvaluationError::InvalidIdentifier { field });
    }
    Ok(())
}

fn validate_revision(value: &str, field: &'static str) -> Result<(), LangSmithEvaluationError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:@/+~-".contains(&byte))
    {
        return Err(LangSmithEvaluationError::InvalidRevision { field });
    }
    Ok(())
}

fn validate_host(value: &str) -> Result<(), LangSmithEvaluationError> {
    let remainder = value
        .strip_prefix("https://")
        .ok_or(LangSmithEvaluationError::InvalidHost)?;
    if remainder.is_empty()
        || remainder.contains('/')
        || remainder.contains('?')
        || remainder.contains('#')
        || remainder.contains(':')
        || remainder.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(LangSmithEvaluationError::InvalidHost);
    }
    if remainder.starts_with('.')
        || remainder.ends_with('.')
        || remainder.split('.').any(|label| {
            label.is_empty()
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(LangSmithEvaluationError::InvalidHost);
    }
    Ok(())
}
