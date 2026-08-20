//! Layer 1 Temporal durable Mission worker contracts and deterministic seams.
//!
//! This crate is intentionally standalone. It compiles a typed Mission/Worker
//! plan into a proposal that names Temporal Workflows, Activities, Signals,
//! Queries, Timers, retries, heartbeats, Continue-As-New, and cancellation.
//! It records only digests and typed metadata; it does not connect to Temporal
//! Cloud, speak gRPC, start a native worker, or claim provider execution.

#![deny(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;

pub const CONTRACT_SCHEMA_VERSION: &str = "hartevo-temporal-worker-plugin-contract/v1";
pub const CONTRACT_VERSION: &str = "temporal-worker-layer1/v1";
pub const PLUGIN_ID: &str = "hartevo.temporal-worker";
pub const PLUGIN_VERSION: &str = "temporal-worker/v1";
pub const SERVICE_ID: &str = "DurableWorkerService";
pub const PROVIDER_ID: &str = "temporal";
pub const PROVIDER_VERSION: &str = "temporal-provider/v1";
pub const API_VERSION: &str = "temporal-workflow-api/v1";
pub const CONSUMER_ID: &str = "MissionWorkerConsumer";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/temporal-worker/worker.v1.json");
pub const NATIVE_GAP: &str = "BLOCKED_ENV: real Temporal gRPC, Temporal Cloud, and a native worker are not available in Layer 1";
const MAX_IDENTIFIER_BYTES: usize = 128;

/// SHA-256 digest used for immutable bindings and opaque payload references.
#[derive(Clone, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest(String);

impl Digest {
    /// Hash bytes without retaining the bytes in a receipt.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(hex::encode(Sha256::digest(bytes)))
    }

    /// Hash a JSON-serializable value using serde's deterministic field order.
    pub fn from_serializable<T: Serialize + ?Sized>(value: &T) -> Self {
        let bytes = serde_json::to_vec(value).expect("typed Temporal values serialize");
        Self::from_bytes(&bytes)
    }

    /// Borrow the lowercase hexadecimal digest.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(&self, field: &'static str) -> Result<(), TemporalWorkerError> {
        if is_digest(self.as_str()) {
            Ok(())
        } else {
            Err(TemporalWorkerError::InvalidDigest { field })
        }
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

/// The typed error taxonomy used by the service, provider, consumer, and fake.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TemporalWorkerError {
    #[error("invalid {field}: {detail}")]
    InvalidInput { field: &'static str, detail: String },
    #[error("invalid digest in {field}")]
    InvalidDigest { field: &'static str },
    #[error("digest mismatch in {field}")]
    DigestMismatch { field: &'static str },
    #[error("provider manifest mismatch: {detail}")]
    ProviderManifestMismatch { detail: String },
    #[error("registration scope mismatch: {detail}")]
    ScopeMismatch { detail: String },
    #[error("provider registration is revoked")]
    ProviderRevoked,
    #[error("Temporal environment is blocked")]
    BlockedEnv,
    #[error("transport error: {detail}")]
    Transport { detail: String },
    #[error("replay conflict for an existing idempotency key")]
    ReplayConflict,
    #[error("recorded history is invalid: {detail}")]
    HistoryViolation { detail: String },
    #[error("recovery requires a recorded StartWorkflow event")]
    MissingStart,
    #[error("uncertain replay is not permitted")]
    UncertainReplay,
}

/// A provider's evidence provenance. None of the Layer 1 values are native.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Recording,
    Fixture,
    ControlledProvider,
    BlockedEnv,
}

impl ProviderProvenance {
    /// Native/provider-connected claims remain false for every Layer 1 value.
    pub const fn is_native(self) -> bool {
        false
    }

    const fn is_blocked(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

/// The external Temporal concepts represented by the Layer 1 proposal.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TemporalOperation {
    StartWorkflow,
    SignalWorkflow,
    QueryWorkflow,
    StartTimer,
    ScheduleActivity,
    ActivityHeartbeat,
    ContinueAsNew,
    CancelWorkflow,
    RecoverWorkflow,
    CompleteWorkflow,
}

/// Typed immutable Workflow namespace/task-queue/id scope.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WorkflowScope {
    pub namespace: String,
    pub task_queue: String,
    pub workflow_id: String,
}

impl WorkflowScope {
    /// Construct and validate a Temporal workflow scope.
    pub fn new(
        namespace: impl Into<String>,
        task_queue: impl Into<String>,
        workflow_id: impl Into<String>,
    ) -> Result<Self, TemporalWorkerError> {
        let scope = Self {
            namespace: namespace.into(),
            task_queue: task_queue.into(),
            workflow_id: workflow_id.into(),
        };
        scope.validate()?;
        Ok(scope)
    }

    /// Hash the complete namespace/task-queue/workflow-id boundary.
    pub fn digest(&self) -> Digest {
        Digest::from_serializable(&(&self.namespace, &self.task_queue, &self.workflow_id))
    }

    /// Validate all scope components.
    pub fn validate(&self) -> Result<(), TemporalWorkerError> {
        validate_temporal_name(&self.namespace, "namespace")?;
        validate_temporal_name(&self.task_queue, "task_queue")?;
        validate_temporal_name(&self.workflow_id, "workflow_id")
    }
}

/// Opaque provider-bound secret identity. It cannot contain credential bytes.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SecretReference {
    pub reference_id: String,
    pub scope_digest: Digest,
    pub credential_revision: u64,
}

impl SecretReference {
    /// Bind a reference to a workflow scope without resolving its secret.
    pub fn for_scope(
        reference_id: impl Into<String>,
        scope: &WorkflowScope,
        credential_revision: u64,
    ) -> Result<Self, TemporalWorkerError> {
        let reference = Self {
            reference_id: reference_id.into(),
            scope_digest: scope.digest(),
            credential_revision,
        };
        reference.validate()?;
        Ok(reference)
    }

    /// Validate the opaque reference and its scope binding.
    pub fn validate(&self) -> Result<(), TemporalWorkerError> {
        if !self.reference_id.starts_with("secret-ref-") {
            return Err(TemporalWorkerError::InvalidInput {
                field: "reference_id",
                detail: "must start with secret-ref-".to_owned(),
            });
        }
        validate_temporal_name(&self.reference_id, "reference_id")?;
        self.scope_digest.validate("scope_digest")?;
        if self.credential_revision == 0 {
            return Err(TemporalWorkerError::InvalidInput {
                field: "credential_revision",
                detail: "must be positive".to_owned(),
            });
        }
        Ok(())
    }
}

/// Typed capability advertised by the Temporal provider manifest.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TemporalCapability {
    Workflow,
    Activity,
    Signal,
    Query,
    Timer,
    RetryPolicy,
    Heartbeat,
    ContinueAsNew,
    Cancellation,
    RecoveryVerification,
}

/// Versioned, digest-bound provider manifest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TemporalProviderManifest {
    pub provider_id: String,
    pub provider_version: String,
    pub api_version: String,
    pub capabilities: BTreeSet<TemporalCapability>,
    pub manifest_digest: Digest,
}

#[derive(Serialize)]
struct ManifestIdentity<'a> {
    provider_id: &'a str,
    provider_version: &'a str,
    api_version: &'a str,
    capabilities: &'a BTreeSet<TemporalCapability>,
}

impl TemporalProviderManifest {
    /// The Layer 1 Temporal manifest and its deterministic capability set.
    pub fn layer1() -> Self {
        let capabilities = [
            TemporalCapability::Workflow,
            TemporalCapability::Activity,
            TemporalCapability::Signal,
            TemporalCapability::Query,
            TemporalCapability::Timer,
            TemporalCapability::RetryPolicy,
            TemporalCapability::Heartbeat,
            TemporalCapability::ContinueAsNew,
            TemporalCapability::Cancellation,
            TemporalCapability::RecoveryVerification,
        ]
        .into_iter()
        .collect();
        let identity = ManifestIdentity {
            provider_id: PROVIDER_ID,
            provider_version: PROVIDER_VERSION,
            api_version: API_VERSION,
            capabilities: &capabilities,
        };
        let manifest_digest = Digest::from_serializable(&identity);
        Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_version: PROVIDER_VERSION.to_owned(),
            api_version: API_VERSION.to_owned(),
            capabilities,
            manifest_digest,
        }
    }

    /// Validate the manifest version and digest.
    pub fn validate(&self) -> Result<(), TemporalWorkerError> {
        validate_temporal_name(&self.provider_id, "provider_id")?;
        validate_temporal_name(&self.provider_version, "provider_version")?;
        validate_temporal_name(&self.api_version, "api_version")?;
        if self.capabilities.is_empty() {
            return Err(TemporalWorkerError::InvalidInput {
                field: "capabilities",
                detail: "must not be empty".to_owned(),
            });
        }
        self.manifest_digest.validate("manifest_digest")?;
        let identity = ManifestIdentity {
            provider_id: &self.provider_id,
            provider_version: &self.provider_version,
            api_version: &self.api_version,
            capabilities: &self.capabilities,
        };
        if self.manifest_digest != Digest::from_serializable(&identity) {
            return Err(TemporalWorkerError::DigestMismatch {
                field: "manifest_digest",
            });
        }
        if self.provider_id != PROVIDER_ID
            || self.provider_version != PROVIDER_VERSION
            || self.api_version != API_VERSION
        {
            return Err(TemporalWorkerError::ProviderManifestMismatch {
                detail: "Layer 1 provider/version/API drifted from the contract".to_owned(),
            });
        }
        Ok(())
    }
}

/// Provider registration. The secret reference is retained only at this
/// boundary and never copied into a proposal or receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TemporalProviderRegistration {
    pub manifest: TemporalProviderManifest,
    pub scope: WorkflowScope,
    pub secret_reference: SecretReference,
    pub registration_digest: Digest,
    pub revoked: bool,
}

#[derive(Serialize)]
struct RegistrationIdentity<'a> {
    manifest_digest: &'a Digest,
    provider_version: &'a str,
    scope: &'a WorkflowScope,
    secret_reference_id: &'a str,
    credential_revision: u64,
}

impl TemporalProviderRegistration {
    /// Create a version-, digest-, scope-, and secret-reference-bound registration.
    pub fn new(
        manifest: TemporalProviderManifest,
        scope: WorkflowScope,
        secret_reference: SecretReference,
    ) -> Result<Self, TemporalWorkerError> {
        let registration = Self {
            manifest,
            scope,
            secret_reference,
            registration_digest: Digest::from_bytes(&[]),
            revoked: false,
        };
        let registration = Self {
            registration_digest: registration.compute_digest(),
            ..registration
        };
        registration.validate()?;
        Ok(registration)
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&RegistrationIdentity {
            manifest_digest: &self.manifest.manifest_digest,
            provider_version: &self.manifest.provider_version,
            scope: &self.scope,
            secret_reference_id: &self.secret_reference.reference_id,
            credential_revision: self.secret_reference.credential_revision,
        })
    }

    /// Validate the registration without resolving credentials.
    pub fn validate(&self) -> Result<(), TemporalWorkerError> {
        self.manifest.validate()?;
        self.scope.validate()?;
        self.secret_reference.validate()?;
        if self.secret_reference.scope_digest != self.scope.digest() {
            return Err(TemporalWorkerError::ScopeMismatch {
                detail: "secret reference is bound to a different workflow scope".to_owned(),
            });
        }
        self.registration_digest.validate("registration_digest")?;
        if self.registration_digest != self.compute_digest() {
            return Err(TemporalWorkerError::DigestMismatch {
                field: "registration_digest",
            });
        }
        Ok(())
    }

    /// Mark the provider registration revoked; revocation is monotonic.
    pub fn revoke(&mut self) {
        self.revoked = true;
    }
}

/// Mission/Worker identity copied into an external proposal by the consumer seam.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MissionWorkerIdentity {
    pub project_id: String,
    pub mission_id: String,
    pub worker_id: String,
    pub revision: u64,
    pub effect_fence: Digest,
}

impl MissionWorkerIdentity {
    /// Construct a typed identity and effect fence.
    pub fn new(
        project_id: impl Into<String>,
        mission_id: impl Into<String>,
        worker_id: impl Into<String>,
        revision: u64,
        effect_fence: Digest,
    ) -> Result<Self, TemporalWorkerError> {
        let identity = Self {
            project_id: project_id.into(),
            mission_id: mission_id.into(),
            worker_id: worker_id.into(),
            revision,
            effect_fence,
        };
        identity.validate()?;
        Ok(identity)
    }

    /// Validate identifiers and monotonic revision.
    pub fn validate(&self) -> Result<(), TemporalWorkerError> {
        validate_temporal_name(&self.project_id, "project_id")?;
        validate_temporal_name(&self.mission_id, "mission_id")?;
        validate_temporal_name(&self.worker_id, "worker_id")?;
        if self.revision == 0 {
            return Err(TemporalWorkerError::InvalidInput {
                field: "revision",
                detail: "must be positive".to_owned(),
            });
        }
        self.effect_fence.validate("effect_fence")
    }
}

/// Deterministic retry policy recorded in the proposal and every attempt fence.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub initial_backoff_ms: u64,
    pub max_backoff_ms: u64,
    pub backoff_multiplier_millis: u32,
}

impl RetryPolicy {
    /// Construct a bounded deterministic retry policy.
    pub fn new(
        max_attempts: u32,
        initial_backoff_ms: u64,
        max_backoff_ms: u64,
        backoff_multiplier_millis: u32,
    ) -> Result<Self, TemporalWorkerError> {
        let policy = Self {
            max_attempts,
            initial_backoff_ms,
            max_backoff_ms,
            backoff_multiplier_millis,
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Return the deterministic delay for a zero-based retry index.
    pub fn delay_for_retry(&self, retry_index: u32) -> u64 {
        let mut delay = self.initial_backoff_ms;
        for _ in 0..retry_index {
            delay = delay
                .saturating_mul(u64::from(self.backoff_multiplier_millis))
                .checked_div(1_000)
                .unwrap_or(self.max_backoff_ms)
                .min(self.max_backoff_ms);
        }
        delay
    }

    /// Validate bounded retry values.
    pub fn validate(&self) -> Result<(), TemporalWorkerError> {
        if self.max_attempts == 0
            || self.initial_backoff_ms == 0
            || self.max_backoff_ms < self.initial_backoff_ms
            || self.backoff_multiplier_millis < 1_000
        {
            return Err(TemporalWorkerError::InvalidInput {
                field: "retry_policy",
                detail: "attempts and backoff bounds are invalid".to_owned(),
            });
        }
        Ok(())
    }
}

/// Deterministic Activity heartbeat policy.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HeartbeatPolicy {
    pub interval_ms: u64,
    pub timeout_ms: u64,
}

impl HeartbeatPolicy {
    /// Construct a heartbeat policy with an explicit timeout.
    pub fn new(interval_ms: u64, timeout_ms: u64) -> Result<Self, TemporalWorkerError> {
        let policy = Self {
            interval_ms,
            timeout_ms,
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Validate heartbeat timing.
    pub fn validate(&self) -> Result<(), TemporalWorkerError> {
        if self.interval_ms == 0 || self.timeout_ms < self.interval_ms {
            return Err(TemporalWorkerError::InvalidInput {
                field: "heartbeat_policy",
                detail: "interval and timeout are invalid".to_owned(),
            });
        }
        Ok(())
    }
}

/// Named signal admitted by a Workflow plan; payloads are digest-only.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SignalDefinition {
    pub name: String,
}

impl SignalDefinition {
    /// Construct a signal definition.
    pub fn new(name: impl Into<String>) -> Result<Self, TemporalWorkerError> {
        let definition = Self { name: name.into() };
        validate_temporal_name(&definition.name, "signal_name")?;
        Ok(definition)
    }
}

/// Named query admitted by a Workflow plan.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct QueryDefinition {
    pub name: String,
}

impl QueryDefinition {
    /// Construct a query definition.
    pub fn new(name: impl Into<String>) -> Result<Self, TemporalWorkerError> {
        let definition = Self { name: name.into() };
        validate_temporal_name(&definition.name, "query_name")?;
        Ok(definition)
    }
}

/// Named deterministic Timer admitted by a Workflow plan.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TimerDefinition {
    pub timer_id: String,
    pub delay_ms: u64,
}

impl TimerDefinition {
    /// Construct a timer definition.
    pub fn new(timer_id: impl Into<String>, delay_ms: u64) -> Result<Self, TemporalWorkerError> {
        let definition = Self {
            timer_id: timer_id.into(),
            delay_ms,
        };
        validate_temporal_name(&definition.timer_id, "timer_id")?;
        if definition.delay_ms == 0 {
            return Err(TemporalWorkerError::InvalidInput {
                field: "delay_ms",
                detail: "must be positive".to_owned(),
            });
        }
        Ok(definition)
    }
}

/// Typed Workflow/Activity/Signal/Query/Timer plan emitted by the consumer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WorkflowPlan {
    pub workflow_name: String,
    pub activity_name: String,
    pub input_digest: Digest,
    pub signals: Vec<SignalDefinition>,
    pub queries: Vec<QueryDefinition>,
    pub timers: Vec<TimerDefinition>,
    pub retry_policy: RetryPolicy,
    pub heartbeat_policy: HeartbeatPolicy,
    pub continue_as_new_after: Option<u32>,
    pub plan_digest: Digest,
}

#[derive(Serialize)]
struct WorkflowPlanIdentity<'a> {
    workflow_name: &'a str,
    activity_name: &'a str,
    input_digest: &'a Digest,
    signals: &'a [SignalDefinition],
    queries: &'a [QueryDefinition],
    timers: &'a [TimerDefinition],
    retry_policy: &'a RetryPolicy,
    heartbeat_policy: &'a HeartbeatPolicy,
    continue_as_new_after: Option<u32>,
}

impl WorkflowPlan {
    /// Build a digest-bound Workflow plan.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        workflow_name: impl Into<String>,
        activity_name: impl Into<String>,
        input_digest: Digest,
        signals: Vec<SignalDefinition>,
        queries: Vec<QueryDefinition>,
        timers: Vec<TimerDefinition>,
        retry_policy: RetryPolicy,
        heartbeat_policy: HeartbeatPolicy,
        continue_as_new_after: Option<u32>,
    ) -> Result<Self, TemporalWorkerError> {
        let plan = Self {
            workflow_name: workflow_name.into(),
            activity_name: activity_name.into(),
            input_digest,
            signals,
            queries,
            timers,
            retry_policy,
            heartbeat_policy,
            continue_as_new_after,
            plan_digest: Digest::from_bytes(&[]),
        };
        plan.validate_without_digest()?;
        let plan = Self {
            plan_digest: plan.compute_digest(),
            ..plan
        };
        plan.validate()?;
        Ok(plan)
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&WorkflowPlanIdentity {
            workflow_name: &self.workflow_name,
            activity_name: &self.activity_name,
            input_digest: &self.input_digest,
            signals: &self.signals,
            queries: &self.queries,
            timers: &self.timers,
            retry_policy: &self.retry_policy,
            heartbeat_policy: &self.heartbeat_policy,
            continue_as_new_after: self.continue_as_new_after,
        })
    }

    /// Validate the complete plan and its immutable digest.
    pub fn validate(&self) -> Result<(), TemporalWorkerError> {
        self.validate_without_digest()?;
        self.plan_digest.validate("plan_digest")?;
        if self.plan_digest != self.compute_digest() {
            return Err(TemporalWorkerError::DigestMismatch {
                field: "plan_digest",
            });
        }
        Ok(())
    }

    fn validate_without_digest(&self) -> Result<(), TemporalWorkerError> {
        validate_temporal_name(&self.workflow_name, "workflow_name")?;
        validate_temporal_name(&self.activity_name, "activity_name")?;
        self.input_digest.validate("input_digest")?;
        self.retry_policy.validate()?;
        self.heartbeat_policy.validate()?;
        validate_unique_names(
            self.signals
                .iter()
                .map(|definition| definition.name.as_str()),
            "signal_name",
        )?;
        validate_unique_names(
            self.queries
                .iter()
                .map(|definition| definition.name.as_str()),
            "query_name",
        )?;
        validate_unique_names(
            self.timers
                .iter()
                .map(|definition| definition.timer_id.as_str()),
            "timer_id",
        )?;
        if self.continue_as_new_after == Some(0) {
            return Err(TemporalWorkerError::InvalidInput {
                field: "continue_as_new_after",
                detail: "must be positive when present".to_owned(),
            });
        }
        Ok(())
    }
}

/// Mission-owned plan input. It is deliberately independent of Domain/Application.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MissionWorkerPlan {
    pub identity: MissionWorkerIdentity,
    pub scope: WorkflowScope,
    pub workflow_name: String,
    pub activity_name: String,
    pub input_digest: Digest,
    pub signals: Vec<SignalDefinition>,
    pub queries: Vec<QueryDefinition>,
    pub timers: Vec<TimerDefinition>,
    pub retry_policy: RetryPolicy,
    pub heartbeat_policy: HeartbeatPolicy,
    pub continue_as_new_after: Option<u32>,
}

impl MissionWorkerPlan {
    /// Construct a Mission/Worker plan without taking effect externally.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        identity: MissionWorkerIdentity,
        scope: WorkflowScope,
        workflow_name: impl Into<String>,
        activity_name: impl Into<String>,
        input_digest: Digest,
        signals: Vec<SignalDefinition>,
        queries: Vec<QueryDefinition>,
        timers: Vec<TimerDefinition>,
        retry_policy: RetryPolicy,
        heartbeat_policy: HeartbeatPolicy,
        continue_as_new_after: Option<u32>,
    ) -> Result<Self, TemporalWorkerError> {
        let plan = Self {
            identity,
            scope,
            workflow_name: workflow_name.into(),
            activity_name: activity_name.into(),
            input_digest,
            signals,
            queries,
            timers,
            retry_policy,
            heartbeat_policy,
            continue_as_new_after,
        };
        plan.validate()?;
        Ok(plan)
    }

    /// Validate the Mission/Worker seam.
    pub fn validate(&self) -> Result<(), TemporalWorkerError> {
        self.identity.validate()?;
        self.scope.validate()?;
        WorkflowPlan::new(
            self.workflow_name.clone(),
            self.activity_name.clone(),
            self.input_digest.clone(),
            self.signals.clone(),
            self.queries.clone(),
            self.timers.clone(),
            self.retry_policy.clone(),
            self.heartbeat_policy.clone(),
            self.continue_as_new_after,
        )?;
        Ok(())
    }

    fn compile_workflow_plan(&self) -> Result<WorkflowPlan, TemporalWorkerError> {
        WorkflowPlan::new(
            self.workflow_name.clone(),
            self.activity_name.clone(),
            self.input_digest.clone(),
            self.signals.clone(),
            self.queries.clone(),
            self.timers.clone(),
            self.retry_policy.clone(),
            self.heartbeat_policy.clone(),
            self.continue_as_new_after,
        )
    }
}

/// Binding copied into every operation and receipt.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReceiptBinding {
    pub project_id: String,
    pub mission_id: String,
    pub worker_id: String,
    pub revision: u64,
    pub effect_fence: Digest,
    pub scope: WorkflowScope,
    pub plan_digest: Digest,
    pub provider_version: String,
    pub provider_manifest_digest: Digest,
}

impl ReceiptBinding {
    /// Bind a Mission/Worker identity to the external provider scope and plan.
    pub fn new(
        identity: &MissionWorkerIdentity,
        scope: WorkflowScope,
        plan_digest: Digest,
        manifest: &TemporalProviderManifest,
    ) -> Result<Self, TemporalWorkerError> {
        let binding = Self {
            project_id: identity.project_id.clone(),
            mission_id: identity.mission_id.clone(),
            worker_id: identity.worker_id.clone(),
            revision: identity.revision,
            effect_fence: identity.effect_fence.clone(),
            scope,
            plan_digest,
            provider_version: manifest.provider_version.clone(),
            provider_manifest_digest: manifest.manifest_digest.clone(),
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Validate every identity, scope, version, and digest binding.
    pub fn validate(&self) -> Result<(), TemporalWorkerError> {
        validate_temporal_name(&self.project_id, "project_id")?;
        validate_temporal_name(&self.mission_id, "mission_id")?;
        validate_temporal_name(&self.worker_id, "worker_id")?;
        if self.revision == 0 {
            return Err(TemporalWorkerError::InvalidInput {
                field: "revision",
                detail: "must be positive".to_owned(),
            });
        }
        self.effect_fence.validate("effect_fence")?;
        self.scope.validate()?;
        self.plan_digest.validate("plan_digest")?;
        validate_temporal_name(&self.provider_version, "provider_version")?;
        self.provider_manifest_digest
            .validate("provider_manifest_digest")
    }

    /// Stable identity digest for receipts and idempotency checks.
    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

/// A proposal is declarative and never implies that a Workflow was started.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WorkflowProposal {
    pub binding: ReceiptBinding,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_manifest_digest: Digest,
    pub workflow_plan: WorkflowPlan,
    pub commands: Vec<WorkflowCommand>,
    pub proposal_digest: Digest,
    pub external_execution: bool,
    pub native: bool,
}

#[derive(Serialize)]
struct ProposalIdentity<'a> {
    binding: &'a ReceiptBinding,
    provider_id: &'a str,
    provider_version: &'a str,
    provider_manifest_digest: &'a Digest,
    workflow_plan: &'a WorkflowPlan,
    commands: &'a [WorkflowCommand],
    external_execution: bool,
    native: bool,
}

impl WorkflowProposal {
    fn new(
        binding: ReceiptBinding,
        manifest: &TemporalProviderManifest,
        workflow_plan: WorkflowPlan,
        commands: Vec<WorkflowCommand>,
    ) -> Result<Self, TemporalWorkerError> {
        let proposal = Self {
            binding,
            provider_id: manifest.provider_id.clone(),
            provider_version: manifest.provider_version.clone(),
            provider_manifest_digest: manifest.manifest_digest.clone(),
            workflow_plan,
            commands,
            proposal_digest: Digest::from_bytes(&[]),
            external_execution: false,
            native: false,
        };
        proposal.validate_without_digest()?;
        let proposal = Self {
            proposal_digest: proposal.compute_digest(),
            ..proposal
        };
        proposal.validate()?;
        Ok(proposal)
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_serializable(&ProposalIdentity {
            binding: &self.binding,
            provider_id: &self.provider_id,
            provider_version: &self.provider_version,
            provider_manifest_digest: &self.provider_manifest_digest,
            workflow_plan: &self.workflow_plan,
            commands: &self.commands,
            external_execution: self.external_execution,
            native: self.native,
        })
    }

    /// Validate that the proposal remains plan-only and digest-bound.
    pub fn validate(&self) -> Result<(), TemporalWorkerError> {
        self.validate_without_digest()?;
        self.proposal_digest.validate("proposal_digest")?;
        if self.proposal_digest != self.compute_digest() {
            return Err(TemporalWorkerError::DigestMismatch {
                field: "proposal_digest",
            });
        }
        Ok(())
    }

    fn validate_without_digest(&self) -> Result<(), TemporalWorkerError> {
        self.binding.validate()?;
        self.workflow_plan.validate()?;
        validate_temporal_name(&self.provider_id, "provider_id")?;
        validate_temporal_name(&self.provider_version, "provider_version")?;
        self.provider_manifest_digest
            .validate("provider_manifest_digest")?;
        if self.external_execution || self.native {
            return Err(TemporalWorkerError::ProviderManifestMismatch {
                detail: "Layer 1 proposals cannot claim external execution or native status"
                    .to_owned(),
            });
        }
        if self.provider_id != PROVIDER_ID
            || self.provider_version != PROVIDER_VERSION
            || self.provider_manifest_digest != self.binding.provider_manifest_digest
        {
            return Err(TemporalWorkerError::ProviderManifestMismatch {
                detail: "proposal provider binding drifted".to_owned(),
            });
        }
        for command in &self.commands {
            command.validate()?;
            if command.binding() != &self.binding {
                return Err(TemporalWorkerError::ScopeMismatch {
                    detail: "proposal command is bound to a different Mission/Workflow".to_owned(),
                });
            }
        }
        Ok(())
    }
}

/// Activity attempt lifecycle used to fence retries and idempotent effects.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivityAttemptStatus {
    Started,
    Retrying,
    Succeeded,
    Failed,
    Cancelled,
}

/// Typed Activity attempt metadata; payload and heartbeat details are digests.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ActivityAttempt {
    pub binding: ReceiptBinding,
    pub activity_id: String,
    pub attempt: u32,
    pub retry_index: u32,
    pub attempt_fence: Digest,
    pub input_digest: Digest,
    pub heartbeat_digest: Option<Digest>,
    pub status: ActivityAttemptStatus,
}

#[derive(Serialize)]
struct AttemptIdentity<'a> {
    binding: &'a ReceiptBinding,
    activity_id: &'a str,
    attempt: u32,
    retry_index: u32,
    input_digest: &'a Digest,
}

impl ActivityAttempt {
    /// Construct an attempt fence from Mission, revision, effect fence, and retry.
    pub fn new(
        binding: ReceiptBinding,
        activity_id: impl Into<String>,
        attempt: u32,
        retry_index: u32,
        input_digest: Digest,
        status: ActivityAttemptStatus,
    ) -> Result<Self, TemporalWorkerError> {
        let attempt = Self {
            binding,
            activity_id: activity_id.into(),
            attempt,
            retry_index,
            attempt_fence: Digest::from_bytes(&[]),
            input_digest,
            heartbeat_digest: None,
            status,
        };
        attempt.validate_without_fence()?;
        let attempt = Self {
            attempt_fence: attempt.compute_fence(),
            ..attempt
        };
        attempt.validate()?;
        Ok(attempt)
    }

    fn compute_fence(&self) -> Digest {
        Digest::from_serializable(&AttemptIdentity {
            binding: &self.binding,
            activity_id: &self.activity_id,
            attempt: self.attempt,
            retry_index: self.retry_index,
            input_digest: &self.input_digest,
        })
    }

    /// Validate attempt and retry fencing.
    pub fn validate(&self) -> Result<(), TemporalWorkerError> {
        self.validate_without_fence()?;
        self.attempt_fence.validate("attempt_fence")?;
        if self.attempt_fence != self.compute_fence() {
            return Err(TemporalWorkerError::DigestMismatch {
                field: "attempt_fence",
            });
        }
        if let Some(heartbeat_digest) = &self.heartbeat_digest {
            heartbeat_digest.validate("heartbeat_digest")?;
        }
        Ok(())
    }

    fn validate_without_fence(&self) -> Result<(), TemporalWorkerError> {
        self.binding.validate()?;
        validate_temporal_name(&self.activity_id, "activity_id")?;
        if self.attempt == 0 {
            return Err(TemporalWorkerError::InvalidInput {
                field: "attempt",
                detail: "must be positive".to_owned(),
            });
        }
        if self.attempt != self.retry_index.saturating_add(1) {
            return Err(TemporalWorkerError::InvalidInput {
                field: "attempt",
                detail: "must equal retry_index + 1".to_owned(),
            });
        }
        self.input_digest.validate("input_digest")
    }
}

/// Signal payload envelope; raw Temporal payload bytes never cross the seam.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SignalEnvelope {
    pub binding: ReceiptBinding,
    pub signal_id: String,
    pub signal_name: String,
    pub payload_digest: Digest,
}

impl SignalEnvelope {
    /// Construct a digest-only Signal envelope.
    pub fn new(
        binding: ReceiptBinding,
        signal_id: impl Into<String>,
        signal_name: impl Into<String>,
        payload_digest: Digest,
    ) -> Result<Self, TemporalWorkerError> {
        let envelope = Self {
            binding,
            signal_id: signal_id.into(),
            signal_name: signal_name.into(),
            payload_digest,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    /// Validate signal identity and payload digest.
    pub fn validate(&self) -> Result<(), TemporalWorkerError> {
        self.binding.validate()?;
        validate_temporal_name(&self.signal_id, "signal_id")?;
        validate_temporal_name(&self.signal_name, "signal_name")?;
        self.payload_digest.validate("payload_digest")
    }
}

/// Declarative Workflow command used by proposals and recording transports.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase", tag = "operation")]
pub enum WorkflowCommand {
    StartWorkflow {
        binding: ReceiptBinding,
        workflow_type: String,
        task_queue: String,
        input_digest: Digest,
    },
    RegisterSignal {
        binding: ReceiptBinding,
        signal_name: String,
    },
    RegisterQuery {
        binding: ReceiptBinding,
        query_name: String,
    },
    StartTimer {
        binding: ReceiptBinding,
        timer_id: String,
        delay_ms: u64,
    },
    ScheduleActivity {
        binding: ReceiptBinding,
        activity: Box<ActivityAttempt>,
        retry_policy: RetryPolicy,
        heartbeat_policy: HeartbeatPolicy,
    },
    SignalWorkflow {
        envelope: SignalEnvelope,
    },
    QueryWorkflow {
        binding: ReceiptBinding,
        query_name: String,
    },
    ActivityHeartbeat {
        binding: ReceiptBinding,
        attempt_fence: Digest,
        heartbeat_digest: Digest,
    },
    ContinueAsNew {
        binding: ReceiptBinding,
        next_plan_digest: Digest,
    },
    CancelWorkflow {
        binding: ReceiptBinding,
        reason_digest: Digest,
    },
    RecoverWorkflow {
        binding: ReceiptBinding,
        recovery_epoch: u64,
        observed_history_digest: Digest,
    },
    CompleteWorkflow {
        binding: ReceiptBinding,
        outcome: OutcomeStatus,
        outcome_digest: Digest,
    },
}

impl WorkflowCommand {
    /// Return the binding associated with this command.
    pub fn binding(&self) -> &ReceiptBinding {
        match self {
            Self::StartWorkflow { binding, .. }
            | Self::RegisterSignal { binding, .. }
            | Self::RegisterQuery { binding, .. }
            | Self::StartTimer { binding, .. }
            | Self::ScheduleActivity { binding, .. }
            | Self::QueryWorkflow { binding, .. }
            | Self::ActivityHeartbeat { binding, .. }
            | Self::ContinueAsNew { binding, .. }
            | Self::CancelWorkflow { binding, .. }
            | Self::RecoverWorkflow { binding, .. }
            | Self::CompleteWorkflow { binding, .. } => binding,
            Self::SignalWorkflow { envelope } => &envelope.binding,
        }
    }

    /// Return the Temporal operation represented by this command.
    pub const fn operation(&self) -> TemporalOperation {
        match self {
            Self::StartWorkflow { .. } => TemporalOperation::StartWorkflow,
            Self::RegisterSignal { .. } | Self::SignalWorkflow { .. } => {
                TemporalOperation::SignalWorkflow
            }
            Self::RegisterQuery { .. } | Self::QueryWorkflow { .. } => {
                TemporalOperation::QueryWorkflow
            }
            Self::StartTimer { .. } => TemporalOperation::StartTimer,
            Self::ScheduleActivity { .. } => TemporalOperation::ScheduleActivity,
            Self::ActivityHeartbeat { .. } => TemporalOperation::ActivityHeartbeat,
            Self::ContinueAsNew { .. } => TemporalOperation::ContinueAsNew,
            Self::CancelWorkflow { .. } => TemporalOperation::CancelWorkflow,
            Self::RecoverWorkflow { .. } => TemporalOperation::RecoverWorkflow,
            Self::CompleteWorkflow { .. } => TemporalOperation::CompleteWorkflow,
        }
    }

    /// Compute a stable idempotency key; no payload is retained.
    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }

    /// Compute the stable semantic idempotency key for this operation.
    pub fn idempotency_key(&self) -> Digest {
        match self {
            Self::StartWorkflow { binding, .. } => {
                Digest::from_serializable(&("start_workflow", &binding.scope))
            }
            Self::RegisterSignal {
                binding,
                signal_name,
            } => Digest::from_serializable(&(
                "register_signal",
                &binding.scope,
                &binding.plan_digest,
                signal_name,
            )),
            Self::RegisterQuery {
                binding,
                query_name,
            } => Digest::from_serializable(&(
                "register_query",
                &binding.scope,
                &binding.plan_digest,
                query_name,
            )),
            Self::StartTimer {
                binding, timer_id, ..
            } => Digest::from_serializable(&("start_timer", &binding.scope, timer_id)),
            Self::ScheduleActivity { activity, .. } => activity.attempt_fence.clone(),
            Self::SignalWorkflow { envelope } => Digest::from_serializable(&(
                "signal_workflow",
                &envelope.binding.scope,
                &envelope.signal_id,
            )),
            Self::QueryWorkflow {
                binding,
                query_name,
            } => Digest::from_serializable(&("query_workflow", &binding.scope, query_name)),
            Self::ActivityHeartbeat {
                binding,
                attempt_fence,
                heartbeat_digest,
            } => Digest::from_serializable(&(
                "activity_heartbeat",
                &binding.scope,
                attempt_fence,
                heartbeat_digest,
            )),
            Self::ContinueAsNew { binding, .. } => {
                Digest::from_serializable(&("continue_as_new", &binding.scope))
            }
            Self::CancelWorkflow { binding, .. } => {
                Digest::from_serializable(&("cancel_workflow", &binding.scope))
            }
            Self::RecoverWorkflow {
                binding,
                recovery_epoch,
                ..
            } => Digest::from_serializable(&("recover_workflow", &binding.scope, recovery_epoch)),
            Self::CompleteWorkflow { binding, .. } => {
                Digest::from_serializable(&("complete_workflow", &binding.scope))
            }
        }
    }

    /// Validate command fields and all nested fences.
    pub fn validate(&self) -> Result<(), TemporalWorkerError> {
        self.binding().validate()?;
        match self {
            Self::StartWorkflow {
                workflow_type,
                task_queue,
                input_digest,
                binding,
            } => {
                validate_temporal_name(workflow_type, "workflow_type")?;
                validate_temporal_name(task_queue, "task_queue")?;
                if task_queue != &binding.scope.task_queue {
                    return Err(TemporalWorkerError::ScopeMismatch {
                        detail: "StartWorkflow task queue drifted from WorkflowScope".to_owned(),
                    });
                }
                input_digest.validate("input_digest")
            }
            Self::RegisterSignal { signal_name, .. } => {
                validate_temporal_name(signal_name, "signal_name")
            }
            Self::RegisterQuery { query_name, .. } | Self::QueryWorkflow { query_name, .. } => {
                validate_temporal_name(query_name, "query_name")
            }
            Self::StartTimer {
                timer_id, delay_ms, ..
            } => {
                validate_temporal_name(timer_id, "timer_id")?;
                if *delay_ms == 0 {
                    return Err(TemporalWorkerError::InvalidInput {
                        field: "delay_ms",
                        detail: "must be positive".to_owned(),
                    });
                }
                Ok(())
            }
            Self::ScheduleActivity {
                activity,
                retry_policy,
                heartbeat_policy,
                ..
            } => {
                activity.validate()?;
                retry_policy.validate()?;
                if activity.retry_index >= retry_policy.max_attempts {
                    return Err(TemporalWorkerError::InvalidInput {
                        field: "retry_index",
                        detail: "retry index exceeds retry policy".to_owned(),
                    });
                }
                heartbeat_policy.validate()
            }
            Self::SignalWorkflow { envelope } => envelope.validate(),
            Self::ActivityHeartbeat {
                attempt_fence,
                heartbeat_digest,
                ..
            } => {
                attempt_fence.validate("attempt_fence")?;
                heartbeat_digest.validate("heartbeat_digest")
            }
            Self::ContinueAsNew {
                next_plan_digest, ..
            } => next_plan_digest.validate("next_plan_digest"),
            Self::CancelWorkflow { reason_digest, .. } => reason_digest.validate("reason_digest"),
            Self::RecoverWorkflow {
                recovery_epoch,
                observed_history_digest,
                ..
            } => {
                if *recovery_epoch == 0 {
                    return Err(TemporalWorkerError::InvalidInput {
                        field: "recovery_epoch",
                        detail: "must be positive".to_owned(),
                    });
                }
                observed_history_digest.validate("observed_history_digest")
            }
            Self::CompleteWorkflow { outcome_digest, .. } => {
                outcome_digest.validate("outcome_digest")
            }
        }
    }
}

/// A recorded fake event with no raw provider payload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RecordedEvent {
    pub sequence: u64,
    pub operation: TemporalOperation,
    pub binding: ReceiptBinding,
    pub idempotency_key: Digest,
    pub command_digest: Digest,
    pub command: WorkflowCommand,
}

impl RecordedEvent {
    fn validate(&self) -> Result<(), TemporalWorkerError> {
        if self.sequence == 0 {
            return Err(TemporalWorkerError::HistoryViolation {
                detail: "event sequence must be positive".to_owned(),
            });
        }
        self.command.validate()?;
        if self.operation != self.command.operation() || self.binding != *self.command.binding() {
            return Err(TemporalWorkerError::HistoryViolation {
                detail: "event metadata does not match its typed command".to_owned(),
            });
        }
        if self.idempotency_key != self.command.idempotency_key() {
            return Err(TemporalWorkerError::HistoryViolation {
                detail: "event idempotency key does not match its command".to_owned(),
            });
        }
        if self.command_digest != self.command.digest() {
            return Err(TemporalWorkerError::HistoryViolation {
                detail: "event command digest does not match its command".to_owned(),
            });
        }
        Ok(())
    }
}

/// Result of a deterministic recording operation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayDisposition {
    Recorded,
    Replayed,
}

/// Provider-neutral receipt for start/signal/query/timer/activity/heartbeat/etc.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RecordReceipt {
    pub binding: ReceiptBinding,
    pub operation: TemporalOperation,
    pub sequence: u64,
    pub command_digest: Digest,
    pub disposition: ReplayDisposition,
    pub provenance: ProviderProvenance,
    pub native: bool,
}

/// Terminal outcome observed by the fake provider; it is not Temporal authority.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeStatus {
    Succeeded,
    Failed,
    Cancelled,
}

/// Explicitly prevents provider history from being mistaken for Hartevo truth.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeAuthority {
    HartevoTruthBoundaryPending,
}

/// Receipt for a verified deterministic recovery sequence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RecoveryReceipt {
    pub binding: ReceiptBinding,
    pub recovery_epoch: u64,
    pub history_digest: Digest,
    pub last_sequence: u64,
    pub recovered_attempts: u32,
    pub retry_count: u32,
    pub recovery_count: u32,
    pub no_uncertain_replay: bool,
    pub record: RecordReceipt,
}

/// Receipt for a terminal outcome candidate.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OutcomeReceipt {
    pub binding: ReceiptBinding,
    pub outcome: OutcomeStatus,
    pub outcome_digest: Digest,
    pub history_digest: Digest,
    pub activity_attempts: u32,
    pub retry_count: u32,
    pub recovery_count: u32,
    pub authority: OutcomeAuthority,
    pub record: RecordReceipt,
}

/// Recovery request tied to the same Mission/Worker revision and effect fence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RecoveryVerificationRequest {
    pub binding: ReceiptBinding,
    pub recovery_epoch: u64,
}

impl RecoveryVerificationRequest {
    /// Construct a recovery verification request.
    pub fn new(binding: ReceiptBinding, recovery_epoch: u64) -> Result<Self, TemporalWorkerError> {
        let request = Self {
            binding,
            recovery_epoch,
        };
        request.binding.validate()?;
        if request.recovery_epoch == 0 {
            return Err(TemporalWorkerError::InvalidInput {
                field: "recovery_epoch",
                detail: "must be positive".to_owned(),
            });
        }
        Ok(request)
    }
}

/// Capabilities exposed by `DurableWorkerService::describe_capabilities`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DurableWorkerCapabilities {
    pub plugin_id: String,
    pub service_id: String,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_manifest_digest: Digest,
    pub operations: BTreeSet<TemporalOperation>,
    pub provenance: ProviderProvenance,
    pub native: Availability,
    pub connected: Availability,
    pub real_grpc: Availability,
    pub external_worker: Availability,
    pub outcome_authority: OutcomeAuthority,
    pub blocked_reason: String,
}

/// Typed availability avoids reducing provider/native state to ambiguous booleans.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Availability {
    Available,
    Unavailable,
}

/// Deterministic transport snapshot suitable for crash/recovery tests.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RecordingSnapshot {
    pub events: Vec<RecordedEvent>,
}

/// Minimal transport boundary. A real gRPC/native implementation is out of scope.
pub trait TemporalTransport: fmt::Debug {
    /// Report provenance without claiming native status.
    fn provenance(&self) -> ProviderProvenance;

    /// Record a typed command or return a fail-closed error.
    fn record(&mut self, command: WorkflowCommand)
    -> Result<TransportReceipt, TemporalWorkerError>;

    /// Borrow deterministic event history.
    fn history(&self) -> &[RecordedEvent];

    /// Export a replayable crash/recovery snapshot.
    fn snapshot(&self) -> RecordingSnapshot;
}

/// Internal transport result before the provider adds binding context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportReceipt {
    pub sequence: u64,
    pub command_digest: Digest,
    pub disposition: ReplayDisposition,
    pub provenance: ProviderProvenance,
}

/// In-memory deterministic recording transport; it is never a native provider.
#[derive(Clone, Debug, Default)]
pub struct RecordingTransport {
    snapshot: RecordingSnapshot,
    command_sequences: BTreeMap<Digest, (Digest, u64)>,
}

impl RecordingTransport {
    /// Create an empty recording transport.
    pub fn new() -> Self {
        Self::default()
    }

    /// Restore a snapshot while validating monotonic history and idempotency.
    pub fn from_snapshot(snapshot: RecordingSnapshot) -> Result<Self, TemporalWorkerError> {
        let mut command_sequences = BTreeMap::new();
        let mut expected_sequence = 1_u64;
        for event in &snapshot.events {
            if event.sequence != expected_sequence {
                return Err(TemporalWorkerError::HistoryViolation {
                    detail: "event sequence is not contiguous".to_owned(),
                });
            }
            event.validate()?;
            if command_sequences
                .insert(
                    event.idempotency_key.clone(),
                    (event.command_digest.clone(), event.sequence),
                )
                .is_some()
            {
                return Err(TemporalWorkerError::ReplayConflict);
            }
            expected_sequence = expected_sequence.saturating_add(1);
        }
        Ok(Self {
            snapshot,
            command_sequences,
        })
    }

    /// Borrow the current recorded events.
    pub fn events(&self) -> &[RecordedEvent] {
        &self.snapshot.events
    }
}

impl TemporalTransport for RecordingTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Recording
    }

    fn record(
        &mut self,
        command: WorkflowCommand,
    ) -> Result<TransportReceipt, TemporalWorkerError> {
        command.validate()?;
        let command_digest = command.digest();
        let idempotency_key = command.idempotency_key();
        if let Some((existing_digest, sequence)) = self.command_sequences.get(&idempotency_key) {
            if existing_digest != &command_digest {
                return Err(TemporalWorkerError::ReplayConflict);
            }
            return Ok(TransportReceipt {
                sequence: *sequence,
                command_digest,
                disposition: ReplayDisposition::Replayed,
                provenance: self.provenance(),
            });
        }
        let sequence = u64::try_from(self.snapshot.events.len())
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| TemporalWorkerError::HistoryViolation {
                detail: "recording sequence overflowed".to_owned(),
            })?;
        let event = RecordedEvent {
            sequence,
            operation: command.operation(),
            binding: command.binding().clone(),
            idempotency_key: idempotency_key.clone(),
            command_digest: command_digest.clone(),
            command,
        };
        event.validate()?;
        self.snapshot.events.push(event);
        self.command_sequences
            .insert(idempotency_key, (command_digest.clone(), sequence));
        Ok(TransportReceipt {
            sequence,
            command_digest,
            disposition: ReplayDisposition::Recorded,
            provenance: self.provenance(),
        })
    }

    fn history(&self) -> &[RecordedEvent] {
        &self.snapshot.events
    }

    fn snapshot(&self) -> RecordingSnapshot {
        self.snapshot.clone()
    }
}

/// Named fake transport wrapper used by tests and controlled harnesses.
#[derive(Clone, Debug, Default)]
pub struct FakeTemporalTransport {
    recording: RecordingTransport,
    fail_next: bool,
}

impl FakeTemporalTransport {
    /// Create a fake with deterministic recording semantics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Make the next command fail transiently without recording it.
    pub fn fail_next_transiently(&mut self) {
        self.fail_next = true;
    }

    /// Borrow the fake event history.
    pub fn events(&self) -> &[RecordedEvent] {
        self.recording.events()
    }
}

impl TemporalTransport for FakeTemporalTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Fixture
    }

    fn record(
        &mut self,
        command: WorkflowCommand,
    ) -> Result<TransportReceipt, TemporalWorkerError> {
        if self.fail_next {
            self.fail_next = false;
            return Err(TemporalWorkerError::Transport {
                detail: "deterministic fake transient transport failure".to_owned(),
            });
        }
        let mut receipt = self.recording.record(command)?;
        receipt.provenance = self.provenance();
        Ok(receipt)
    }

    fn history(&self) -> &[RecordedEvent] {
        self.recording.history()
    }

    fn snapshot(&self) -> RecordingSnapshot {
        self.recording.snapshot()
    }
}

/// Explicit blocked environment transport. It cannot be mistaken for connected.
#[derive(Clone, Debug, Default)]
pub struct BlockedEnvTransport;

impl TemporalTransport for BlockedEnvTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }

    fn record(
        &mut self,
        _command: WorkflowCommand,
    ) -> Result<TransportReceipt, TemporalWorkerError> {
        Err(TemporalWorkerError::BlockedEnv)
    }

    fn history(&self) -> &[RecordedEvent] {
        &[]
    }

    fn snapshot(&self) -> RecordingSnapshot {
        RecordingSnapshot::default()
    }
}

/// Provider state exposed for honest capability reporting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderState {
    RecordingOnly,
    BlockedEnv,
    Revoked,
}

/// Typed provider boundary around a transport and immutable registration.
#[derive(Clone, Debug)]
pub struct TemporalProvider<T> {
    registration: TemporalProviderRegistration,
    transport: T,
    state: ProviderState,
}

impl<T: TemporalTransport> TemporalProvider<T> {
    /// Construct a provider after validating manifest/version/digest/scope.
    pub fn new(
        registration: TemporalProviderRegistration,
        transport: T,
    ) -> Result<Self, TemporalWorkerError> {
        registration.validate()?;
        let state = if transport.provenance().is_blocked() {
            ProviderState::BlockedEnv
        } else {
            ProviderState::RecordingOnly
        };
        Ok(Self {
            registration,
            transport,
            state,
        })
    }

    /// Borrow the provider registration.
    pub fn registration(&self) -> &TemporalProviderRegistration {
        &self.registration
    }

    /// Borrow deterministic history.
    pub fn history(&self) -> &[RecordedEvent] {
        self.transport.history()
    }

    /// Export the underlying recording snapshot.
    pub fn snapshot(&self) -> RecordingSnapshot {
        self.transport.snapshot()
    }

    /// Return provider state.
    pub const fn state(&self) -> ProviderState {
        self.state
    }

    /// Return transport provenance.
    pub fn provenance(&self) -> ProviderProvenance {
        self.transport.provenance()
    }

    /// Revoke all subsequent recording operations.
    pub fn revoke(&mut self) {
        self.registration.revoke();
        self.state = ProviderState::Revoked;
    }

    fn record(&mut self, command: WorkflowCommand) -> Result<RecordReceipt, TemporalWorkerError> {
        self.guard()?;
        command.validate()?;
        let operation = command.operation();
        let binding = command.binding().clone();
        if binding.scope != self.registration.scope {
            return Err(TemporalWorkerError::ScopeMismatch {
                detail: "namespace, task queue, or workflow id drifted".to_owned(),
            });
        }
        if binding.provider_version != self.registration.manifest.provider_version
            || binding.provider_manifest_digest != self.registration.manifest.manifest_digest
        {
            return Err(TemporalWorkerError::ProviderManifestMismatch {
                detail: "provider version or manifest digest drifted".to_owned(),
            });
        }
        let receipt = self.transport.record(command)?;
        Ok(RecordReceipt {
            binding,
            operation,
            sequence: receipt.sequence,
            command_digest: receipt.command_digest,
            disposition: receipt.disposition,
            provenance: receipt.provenance,
            native: receipt.provenance.is_native(),
        })
    }

    fn guard(&self) -> Result<(), TemporalWorkerError> {
        if self.registration.revoked || self.state == ProviderState::Revoked {
            return Err(TemporalWorkerError::ProviderRevoked);
        }
        if self.state == ProviderState::BlockedEnv {
            return Err(TemporalWorkerError::BlockedEnv);
        }
        Ok(())
    }
}

/// Mission consumer seam that performs no external operation.
#[derive(Clone, Debug)]
pub struct MissionWorkerConsumer {
    registration: TemporalProviderRegistration,
}

impl MissionWorkerConsumer {
    /// Bind a consumer to one immutable provider registration.
    pub fn new(registration: TemporalProviderRegistration) -> Result<Self, TemporalWorkerError> {
        registration.validate()?;
        Ok(Self { registration })
    }

    /// Map a Mission/Worker plan to a Temporal Workflow proposal.
    pub fn compile_workflow_proposal(
        &self,
        mission_plan: &MissionWorkerPlan,
    ) -> Result<WorkflowProposal, TemporalWorkerError> {
        mission_plan.validate()?;
        if mission_plan.scope != self.registration.scope {
            return Err(TemporalWorkerError::ScopeMismatch {
                detail: "Mission/Worker plan scope differs from provider registration".to_owned(),
            });
        }
        let workflow_plan = mission_plan.compile_workflow_plan()?;
        let binding = ReceiptBinding::new(
            &mission_plan.identity,
            mission_plan.scope.clone(),
            workflow_plan.plan_digest.clone(),
            &self.registration.manifest,
        )?;
        let mut commands = vec![WorkflowCommand::StartWorkflow {
            binding: binding.clone(),
            workflow_type: workflow_plan.workflow_name.clone(),
            task_queue: binding.scope.task_queue.clone(),
            input_digest: workflow_plan.input_digest.clone(),
        }];
        commands.push(WorkflowCommand::ScheduleActivity {
            binding: binding.clone(),
            activity: Box::new(ActivityAttempt::new(
                binding.clone(),
                workflow_plan.activity_name.clone(),
                1,
                0,
                workflow_plan.input_digest.clone(),
                ActivityAttemptStatus::Started,
            )?),
            retry_policy: workflow_plan.retry_policy.clone(),
            heartbeat_policy: workflow_plan.heartbeat_policy.clone(),
        });
        commands.extend(workflow_plan.signals.iter().cloned().map(|signal| {
            WorkflowCommand::RegisterSignal {
                binding: binding.clone(),
                signal_name: signal.name,
            }
        }));
        commands.extend(workflow_plan.queries.iter().cloned().map(|query| {
            WorkflowCommand::RegisterQuery {
                binding: binding.clone(),
                query_name: query.name,
            }
        }));
        commands.extend(workflow_plan.timers.iter().cloned().map(|timer| {
            WorkflowCommand::StartTimer {
                binding: binding.clone(),
                timer_id: timer.timer_id,
                delay_ms: timer.delay_ms,
            }
        }));
        WorkflowProposal::new(
            binding,
            &self.registration.manifest,
            workflow_plan,
            commands,
        )
    }
}

/// Typed Layer 1 service: compile/read/record/verify only.
#[derive(Clone, Debug)]
pub struct DurableWorkerService<T> {
    provider: TemporalProvider<T>,
}

impl<T: TemporalTransport> DurableWorkerService<T> {
    /// Construct the service around a typed provider and deterministic transport.
    pub fn new(
        registration: TemporalProviderRegistration,
        transport: T,
    ) -> Result<Self, TemporalWorkerError> {
        Ok(Self {
            provider: TemporalProvider::new(registration, transport)?,
        })
    }

    /// Compile a plan without contacting or starting an external Workflow.
    pub fn compile_workflow_proposal(
        &self,
        mission_plan: &MissionWorkerPlan,
    ) -> Result<WorkflowProposal, TemporalWorkerError> {
        MissionWorkerConsumer::new(self.provider.registration().clone())?
            .compile_workflow_proposal(mission_plan)
    }

    /// Describe typed capabilities and the honest native gap.
    pub fn describe_capabilities(&self) -> DurableWorkerCapabilities {
        DurableWorkerCapabilities {
            plugin_id: PLUGIN_ID.to_owned(),
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            provider_version: self
                .provider
                .registration()
                .manifest
                .provider_version
                .clone(),
            provider_manifest_digest: self
                .provider
                .registration()
                .manifest
                .manifest_digest
                .clone(),
            operations: [
                TemporalOperation::StartWorkflow,
                TemporalOperation::SignalWorkflow,
                TemporalOperation::QueryWorkflow,
                TemporalOperation::StartTimer,
                TemporalOperation::ScheduleActivity,
                TemporalOperation::ActivityHeartbeat,
                TemporalOperation::ContinueAsNew,
                TemporalOperation::CancelWorkflow,
                TemporalOperation::RecoverWorkflow,
                TemporalOperation::CompleteWorkflow,
            ]
            .into_iter()
            .collect(),
            provenance: self.provider.provenance(),
            native: Availability::Unavailable,
            connected: Availability::Unavailable,
            real_grpc: Availability::Unavailable,
            external_worker: Availability::Unavailable,
            outcome_authority: OutcomeAuthority::HartevoTruthBoundaryPending,
            blocked_reason: NATIVE_GAP.to_owned(),
        }
    }

    /// Record a typed Signal envelope without retaining its raw payload.
    pub fn record_signal(
        &mut self,
        envelope: SignalEnvelope,
    ) -> Result<RecordReceipt, TemporalWorkerError> {
        self.provider
            .record(WorkflowCommand::SignalWorkflow { envelope })
    }

    /// Record a proposal's StartWorkflow mapping.
    pub fn record_start(
        &mut self,
        proposal: &WorkflowProposal,
    ) -> Result<RecordReceipt, TemporalWorkerError> {
        proposal.validate()?;
        self.provider.record(WorkflowCommand::StartWorkflow {
            binding: proposal.binding.clone(),
            workflow_type: proposal.workflow_plan.workflow_name.clone(),
            task_queue: proposal.binding.scope.task_queue.clone(),
            input_digest: proposal.workflow_plan.input_digest.clone(),
        })
    }

    /// Record a query observation by name and binding.
    pub fn record_query(
        &mut self,
        binding: ReceiptBinding,
        query_name: impl Into<String>,
    ) -> Result<RecordReceipt, TemporalWorkerError> {
        self.provider.record(WorkflowCommand::QueryWorkflow {
            binding,
            query_name: query_name.into(),
        })
    }

    /// Record a deterministic Timer start.
    pub fn record_timer(
        &mut self,
        binding: ReceiptBinding,
        timer_id: impl Into<String>,
        delay_ms: u64,
    ) -> Result<RecordReceipt, TemporalWorkerError> {
        self.provider.record(WorkflowCommand::StartTimer {
            binding,
            timer_id: timer_id.into(),
            delay_ms,
        })
    }

    /// Record an Activity attempt, including a retry index and attempt fence.
    pub fn record_activity_attempt(
        &mut self,
        attempt: ActivityAttempt,
        retry_policy: RetryPolicy,
        heartbeat_policy: HeartbeatPolicy,
    ) -> Result<RecordReceipt, TemporalWorkerError> {
        self.provider.record(WorkflowCommand::ScheduleActivity {
            binding: attempt.binding.clone(),
            activity: Box::new(attempt),
            retry_policy,
            heartbeat_policy,
        })
    }

    /// Record a digest-only Activity heartbeat.
    pub fn record_heartbeat(
        &mut self,
        binding: ReceiptBinding,
        attempt_fence: Digest,
        heartbeat_digest: Digest,
    ) -> Result<RecordReceipt, TemporalWorkerError> {
        self.provider.record(WorkflowCommand::ActivityHeartbeat {
            binding,
            attempt_fence,
            heartbeat_digest,
        })
    }

    /// Record Continue-As-New with a next-plan digest.
    pub fn record_continue_as_new(
        &mut self,
        binding: ReceiptBinding,
        next_plan_digest: Digest,
    ) -> Result<RecordReceipt, TemporalWorkerError> {
        self.provider.record(WorkflowCommand::ContinueAsNew {
            binding,
            next_plan_digest,
        })
    }

    /// Record cancellation with a digest-only reason.
    pub fn record_cancel(
        &mut self,
        binding: ReceiptBinding,
        reason_digest: Digest,
    ) -> Result<RecordReceipt, TemporalWorkerError> {
        self.provider.record(WorkflowCommand::CancelWorkflow {
            binding,
            reason_digest,
        })
    }

    /// Verify a crash/recovery history and record a recovery receipt.
    pub fn verify_recovery(
        &mut self,
        request: RecoveryVerificationRequest,
    ) -> Result<RecoveryReceipt, TemporalWorkerError> {
        request.binding.validate()?;
        let (history_digest, last_sequence, attempts, retries, recoveries) =
            verify_history(self.provider.history(), &request.binding)?;
        let record = self.provider.record(WorkflowCommand::RecoverWorkflow {
            binding: request.binding.clone(),
            recovery_epoch: request.recovery_epoch,
            observed_history_digest: history_digest.clone(),
        })?;
        Ok(RecoveryReceipt {
            binding: request.binding,
            recovery_epoch: request.recovery_epoch,
            history_digest,
            last_sequence,
            recovered_attempts: attempts,
            retry_count: retries,
            recovery_count: recoveries.saturating_add(1),
            no_uncertain_replay: true,
            record,
        })
    }

    /// Record a terminal outcome candidate, explicitly below Hartevo truth authority.
    pub fn record_outcome(
        &mut self,
        binding: ReceiptBinding,
        outcome: OutcomeStatus,
        outcome_digest: Digest,
    ) -> Result<OutcomeReceipt, TemporalWorkerError> {
        outcome_digest.validate("outcome_digest")?;
        verify_history(self.provider.history(), &binding)?;
        let record = self.provider.record(WorkflowCommand::CompleteWorkflow {
            binding: binding.clone(),
            outcome,
            outcome_digest: outcome_digest.clone(),
        })?;
        let (history_digest, _, attempts, retries, recoveries) =
            verify_history(self.provider.history(), &binding)?;
        Ok(OutcomeReceipt {
            binding,
            outcome,
            outcome_digest,
            history_digest,
            activity_attempts: attempts,
            retry_count: retries,
            recovery_count: recoveries,
            authority: OutcomeAuthority::HartevoTruthBoundaryPending,
            record,
        })
    }

    /// Borrow the provider for tests and future composition.
    pub fn provider(&self) -> &TemporalProvider<T> {
        &self.provider
    }

    /// Mutably borrow the provider for revocation and controlled transport tests.
    pub fn provider_mut(&mut self) -> &mut TemporalProvider<T> {
        &mut self.provider
    }
}

fn verify_history(
    history: &[RecordedEvent],
    binding: &ReceiptBinding,
) -> Result<(Digest, u64, u32, u32, u32), TemporalWorkerError> {
    binding.validate()?;
    if history.is_empty() {
        return Err(TemporalWorkerError::MissingStart);
    }
    let mut expected_sequence = 1_u64;
    let mut has_start = false;
    let mut attempt_fences = BTreeSet::new();
    let mut attempts = 0_u32;
    let mut retries = 0_u32;
    let mut recoveries = 0_u32;
    for event in history {
        event.validate()?;
        if event.sequence != expected_sequence {
            return Err(TemporalWorkerError::HistoryViolation {
                detail: "event sequence is not contiguous".to_owned(),
            });
        }
        if event.binding != *binding {
            return Err(TemporalWorkerError::ScopeMismatch {
                detail: "history contains a different Mission/Workflow binding".to_owned(),
            });
        }
        if matches!(event.operation, TemporalOperation::StartWorkflow) {
            has_start = true;
        }
        match &event.command {
            WorkflowCommand::ScheduleActivity { activity, .. } => {
                if !attempt_fences.insert(activity.attempt_fence.clone()) {
                    return Err(TemporalWorkerError::HistoryViolation {
                        detail: "activity attempt fence was reused".to_owned(),
                    });
                }
                attempts = attempts.saturating_add(1);
                if activity.retry_index > 0 {
                    retries = retries.saturating_add(1);
                }
            }
            WorkflowCommand::RecoverWorkflow { .. } => {
                recoveries = recoveries.saturating_add(1);
            }
            _ => {}
        }
        expected_sequence = expected_sequence.saturating_add(1);
    }
    if !has_start {
        return Err(TemporalWorkerError::MissingStart);
    }
    let last_sequence = expected_sequence.saturating_sub(1);
    Ok((
        Digest::from_serializable(history),
        last_sequence,
        attempts,
        retries,
        recoveries,
    ))
}

fn validate_temporal_name(value: &str, field: &'static str) -> Result<(), TemporalWorkerError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/'))
    {
        return Err(TemporalWorkerError::InvalidInput {
            field,
            detail: "must be 1..128 ASCII letters, digits, dot, underscore, hyphen, or slash"
                .to_owned(),
        });
    }
    Ok(())
}

fn validate_unique_names<'a>(
    values: impl IntoIterator<Item = &'a str>,
    field: &'static str,
) -> Result<(), TemporalWorkerError> {
    let mut names = BTreeSet::new();
    for value in values {
        validate_temporal_name(value, field)?;
        if !names.insert(value) {
            return Err(TemporalWorkerError::InvalidInput {
                field,
                detail: "duplicate name".to_owned(),
            });
        }
    }
    Ok(())
}

fn is_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contract_is_embedded_and_native_claims_are_false() {
        let contract: serde_json::Value = serde_json::from_str(CONTRACT_JSON).expect("contract");
        assert_eq!(contract["schemaVersion"], CONTRACT_SCHEMA_VERSION);
        assert!(!ProviderProvenance::Recording.is_native());
        assert!(!ProviderProvenance::Fixture.is_native());
        assert!(!ProviderProvenance::BlockedEnv.is_native());
    }

    #[test]
    fn retry_delay_is_deterministic_and_bounded() {
        let policy = RetryPolicy::new(4, 100, 250, 2_000).expect("policy");
        assert_eq!(policy.delay_for_retry(0), 100);
        assert_eq!(policy.delay_for_retry(1), 200);
        assert_eq!(policy.delay_for_retry(2), 250);
        assert_eq!(policy.delay_for_retry(10), 250);
    }
}
