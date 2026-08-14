use std::{
    collections::BTreeMap,
    fmt,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use serde_json::{Map, Value};
use url::Url;
use zeroize::Zeroizing;

use crate::error::{TerraformCloudRunError, TerraformCloudTransportError};
use crate::{
    ApplyEvidence, ApplyId, ConfigurationSource, ConfigurationVersionFence, ConfigurationVersionId,
    CostAvailability, CostEvidence, Digest, LockIdentity, PlanEvidence, PlanId, PlanStatus,
    PolicyEvidence, PolicyResult, PolicySetId, ProviderProvenance, RunEvidence, RunId, RunMode,
    StatusTransition, TerraformCloudScope, TerraformRunStatus, WorkspaceId, WorkspaceRevision,
};

/// Credential material is resolved for one provider call and is never part of
/// a registration, receipt, debug representation, or transport call record.
#[derive(Clone)]
pub struct SecretMaterial(Zeroizing<String>);

impl SecretMaterial {
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for SecretMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretMaterial(<redacted>)")
    }
}

/// The only transport methods in Layer 1 are bounded, metadata-only reads.
/// There is deliberately no upload, create, cancel, discard, apply, or
/// workspace/variable/state mutation method in this trait.
pub trait TerraformCloudRunTransport: fmt::Debug + Send + Sync {
    fn provenance(&self) -> ProviderProvenance;

    fn describe_workspace(
        &self,
        token: &SecretMaterial,
        scope: &TerraformCloudScope,
    ) -> Result<TerraformCloudWorkspaceApiRecord, TerraformCloudTransportError>;

    fn read_run_evidence(
        &self,
        token: &SecretMaterial,
        scope: &TerraformCloudScope,
    ) -> Result<RunEvidence, TerraformCloudTransportError>;
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct TerraformCloudWorkspaceApiRecord {
    pub workspace_id: WorkspaceId,
    pub workspace_revision: WorkspaceRevision,
    pub lock_identity: LockIdentity,
    pub locked: bool,
    pub execution_mode: String,
    pub terraform_version: Option<String>,
    pub configuration_version: Option<ConfigurationVersionId>,
    pub current_run: Option<RunId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerraformCloudTransportOperation {
    DescribeWorkspace,
    ReadRunEvidence,
}

/// Deterministic recording/fixture transport. Its provenance is explicit and
/// can never become native or Connected evidence.
#[derive(Clone)]
pub struct RecordingTerraformCloudTransport {
    workspace: Arc<Mutex<TerraformCloudWorkspaceApiRecord>>,
    evidence: Arc<Mutex<RunEvidence>>,
    provenance: ProviderProvenance,
    fault: Arc<Mutex<Option<TerraformCloudTransportError>>>,
    operations: Arc<Mutex<Vec<TerraformCloudTransportOperation>>>,
}

impl fmt::Debug for RecordingTerraformCloudTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordingTerraformCloudTransport")
            .field("provenance", &self.provenance)
            .field("operations", &self.operations().len())
            .finish_non_exhaustive()
    }
}

impl RecordingTerraformCloudTransport {
    pub fn new(
        workspace: TerraformCloudWorkspaceApiRecord,
        evidence: RunEvidence,
        provenance: ProviderProvenance,
    ) -> Self {
        assert!(matches!(
            provenance,
            ProviderProvenance::Recording
                | ProviderProvenance::Fixture
                | ProviderProvenance::Loopback
                | ProviderProvenance::BlockedEnv
        ));
        Self {
            workspace: Arc::new(Mutex::new(workspace)),
            evidence: Arc::new(Mutex::new(evidence)),
            provenance,
            fault: Arc::new(Mutex::new(None)),
            operations: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn recording(workspace: TerraformCloudWorkspaceApiRecord, evidence: RunEvidence) -> Self {
        Self::new(workspace, evidence, ProviderProvenance::Recording)
    }

    pub fn fixture(workspace: TerraformCloudWorkspaceApiRecord, evidence: RunEvidence) -> Self {
        Self::new(workspace, evidence, ProviderProvenance::Fixture)
    }

    pub fn loopback(workspace: TerraformCloudWorkspaceApiRecord, evidence: RunEvidence) -> Self {
        Self::new(workspace, evidence, ProviderProvenance::Loopback)
    }

    pub fn blocked_env(workspace: TerraformCloudWorkspaceApiRecord, evidence: RunEvidence) -> Self {
        Self::new(workspace, evidence, ProviderProvenance::BlockedEnv)
    }

    pub fn set_fault(&self, fault: TerraformCloudTransportError) {
        if let Ok(mut value) = self.fault.lock() {
            *value = Some(fault);
        }
    }

    pub fn clear_fault(&self) {
        if let Ok(mut value) = self.fault.lock() {
            *value = None;
        }
    }

    pub fn set_evidence(&self, evidence: RunEvidence) {
        if let Ok(mut value) = self.evidence.lock() {
            *value = evidence;
        }
    }

    pub fn set_workspace(&self, workspace: TerraformCloudWorkspaceApiRecord) {
        if let Ok(mut value) = self.workspace.lock() {
            *value = workspace;
        }
    }

    pub fn operations(&self) -> Vec<TerraformCloudTransportOperation> {
        self.operations
            .lock()
            .map_or_else(|_| Vec::new(), |operations| operations.clone())
    }

    fn before_call(
        &self,
        operation: TerraformCloudTransportOperation,
        token: &SecretMaterial,
    ) -> Result<(), TerraformCloudTransportError> {
        self.operations
            .lock()
            .map_err(|_| TerraformCloudTransportError::Network)?
            .push(operation);
        if token.as_str().trim().is_empty() || token.as_str().chars().any(char::is_control) {
            return Err(TerraformCloudTransportError::Unauthorized);
        }
        self.fault
            .lock()
            .map_err(|_| TerraformCloudTransportError::Network)?
            .clone()
            .map_or(Ok(()), Err)
    }
}

impl TerraformCloudRunTransport for RecordingTerraformCloudTransport {
    fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }

    fn describe_workspace(
        &self,
        token: &SecretMaterial,
        _scope: &TerraformCloudScope,
    ) -> Result<TerraformCloudWorkspaceApiRecord, TerraformCloudTransportError> {
        self.before_call(TerraformCloudTransportOperation::DescribeWorkspace, token)?;
        self.workspace
            .lock()
            .map_err(|_| TerraformCloudTransportError::Network)
            .map(|workspace| workspace.clone())
    }

    fn read_run_evidence(
        &self,
        token: &SecretMaterial,
        _scope: &TerraformCloudScope,
    ) -> Result<RunEvidence, TerraformCloudTransportError> {
        self.before_call(TerraformCloudTransportOperation::ReadRunEvidence, token)?;
        self.evidence
            .lock()
            .map_err(|_| TerraformCloudTransportError::Network)
            .map(|evidence| evidence.clone())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    pub max_attempts: u8,
    pub initial_backoff_ms: u64,
}

impl RetryPolicy {
    pub const fn bounded() -> Self {
        Self {
            max_attempts: 3,
            initial_backoff_ms: 100,
        }
    }

    pub fn new(max_attempts: u8, initial_backoff_ms: u64) -> Result<Self, TerraformCloudRunError> {
        if max_attempts == 0 || max_attempts > 5 {
            return Err(TerraformCloudRunError::InvalidInput {
                field: "retry policy",
                reason: "attempts must be between one and five",
            });
        }
        Ok(Self {
            max_attempts,
            initial_backoff_ms,
        })
    }

    fn delay_for_attempt(self, attempt: u8) -> Duration {
        let exponent = u32::from(attempt.saturating_sub(1)).min(5);
        Duration::from_millis(self.initial_backoff_ms.saturating_mul(1_u64 << exponent))
    }
}

/// Official HCP Terraform JSON:API read transport. Its constructor validates
/// HTTPS, while a separately named loopback constructor is controlled test
/// evidence and is never reported as native or Connected.
pub struct UreqTerraformCloudTransport {
    base_url: String,
    agent: ureq::Agent,
    retry_policy: RetryPolicy,
    provenance: ProviderProvenance,
}

impl fmt::Debug for UreqTerraformCloudTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UreqTerraformCloudTransport")
            .field("base_url", &self.base_url)
            .field("retry_policy", &self.retry_policy)
            .field("provenance", &self.provenance)
            .finish_non_exhaustive()
    }
}

impl UreqTerraformCloudTransport {
    pub fn new(base_url: impl Into<String>) -> Result<Self, TerraformCloudRunError> {
        let base_url = base_url.into();
        Self::build(&base_url, false)
    }

    pub fn new_loopback(base_url: impl Into<String>) -> Result<Self, TerraformCloudRunError> {
        let base_url = base_url.into();
        Self::build(&base_url, true)
    }

    pub fn with_retry_policy(
        mut self,
        retry_policy: RetryPolicy,
    ) -> Result<Self, TerraformCloudRunError> {
        self.retry_policy = retry_policy;
        Ok(self)
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    fn build(base_url: &str, loopback: bool) -> Result<Self, TerraformCloudRunError> {
        let base_url = base_url.trim_end_matches('/').to_owned();
        let parsed = Url::parse(&base_url).map_err(|_| TerraformCloudRunError::InvalidHostname)?;
        let host = parsed
            .host_str()
            .ok_or(TerraformCloudRunError::InvalidHostname)?;
        if parsed.username() != ""
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(TerraformCloudRunError::InvalidHostname);
        }
        if loopback {
            if parsed.scheme() != "http" || !is_loopback_host(host) {
                return Err(TerraformCloudRunError::InvalidHostname);
            }
        } else if parsed.scheme() != "https" {
            return Err(TerraformCloudRunError::InvalidHostname);
        }
        let agent = ureq::Agent::config_builder()
            .user_agent("hartevo-terraform-cloud-run/1")
            .timeout_global(Some(Duration::from_secs(30)))
            .build()
            .into();
        Ok(Self {
            base_url,
            agent,
            retry_policy: RetryPolicy::bounded(),
            provenance: if loopback {
                ProviderProvenance::Loopback
            } else {
                ProviderProvenance::OfficialHttps
            },
        })
    }

    fn endpoint(&self, segments: &[&str]) -> Result<String, TerraformCloudTransportError> {
        let mut url = Url::parse(&self.base_url)
            .map_err(|_| TerraformCloudTransportError::InvalidConfiguration)?;
        {
            let mut path = url
                .path_segments_mut()
                .map_err(|()| TerraformCloudTransportError::InvalidConfiguration)?;
            for segment in segments {
                path.push(segment);
            }
        }
        Ok(url.to_string())
    }

    fn get_json(
        &self,
        token: &SecretMaterial,
        segments: &[&str],
    ) -> Result<Value, TerraformCloudTransportError> {
        let url = self.endpoint(segments)?;
        let mut attempt = 1;
        loop {
            let request = self
                .agent
                .get(&url)
                .header("Authorization", format!("Bearer {}", token.as_str()))
                .header("Accept", "application/vnd.api+json")
                .header("X-Hartevo-Client", "hartevo-terraform-cloud-run/1");
            match request.call() {
                Ok(mut response) => {
                    let body = response
                        .body_mut()
                        .read_to_string()
                        .map_err(|_| TerraformCloudTransportError::Network)?;
                    if body.len() > crate::MAX_RESPONSE_BYTES {
                        return Err(TerraformCloudTransportError::ResponseTooLarge);
                    }
                    return serde_json::from_str(&body)
                        .map_err(|_| TerraformCloudTransportError::Decode);
                }
                Err(error) => {
                    let classified = classify_http_error(&error);
                    if !is_retryable(&classified) || attempt >= self.retry_policy.max_attempts {
                        return if is_retryable(&classified) && self.retry_policy.max_attempts > 1 {
                            Err(TerraformCloudTransportError::ServerUnavailable)
                        } else {
                            Err(classified)
                        };
                    }
                    let delay = self.retry_policy.delay_for_attempt(attempt);
                    if !delay.is_zero() {
                        thread::sleep(delay);
                    }
                    attempt = attempt.saturating_add(1);
                }
            }
        }
    }

    fn resource(
        &self,
        token: &SecretMaterial,
        segments: &[&str],
    ) -> Result<(String, Map<String, Value>), TerraformCloudTransportError> {
        let document = self.get_json(token, segments)?;
        let data = document
            .get("data")
            .and_then(Value::as_object)
            .ok_or(TerraformCloudTransportError::Decode)?;
        let id = data
            .get("id")
            .and_then(Value::as_str)
            .ok_or(TerraformCloudTransportError::Decode)?
            .to_owned();
        let attributes = data
            .get("attributes")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        Ok((id, attributes))
    }

    fn relationship_id(
        &self,
        token: &SecretMaterial,
        segments: &[&str],
        relationship: &str,
    ) -> Result<Option<String>, TerraformCloudTransportError> {
        let document = self.get_json(token, segments)?;
        Ok(document
            .get("data")
            .and_then(Value::as_object)
            .and_then(|data| data.get("relationships"))
            .and_then(Value::as_object)
            .and_then(|relationships| relationships.get(relationship))
            .and_then(Value::as_object)
            .and_then(|relationship| relationship.get("data"))
            .and_then(Value::as_object)
            .and_then(|data| data.get("id"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned))
    }
}

impl TerraformCloudRunTransport for UreqTerraformCloudTransport {
    fn provenance(&self) -> ProviderProvenance {
        self.provenance
    }

    fn describe_workspace(
        &self,
        token: &SecretMaterial,
        scope: &TerraformCloudScope,
    ) -> Result<TerraformCloudWorkspaceApiRecord, TerraformCloudTransportError> {
        let segments = [
            "organizations",
            scope.organization.as_str(),
            "workspaces",
            scope.workspace.as_str(),
        ];
        let (id, attributes) = self.resource(token, &segments)?;
        let workspace_id =
            WorkspaceId::new(id).map_err(|_| TerraformCloudTransportError::Decode)?;
        let updated_at = string_attribute(&attributes, "updated-at");
        let workspace_revision = WorkspaceRevision::new(
            updated_at.unwrap_or_else(|| Digest::from_serializable(&attributes).to_string()),
        )
        .map_err(|_| TerraformCloudTransportError::Decode)?;
        let locked = attributes
            .get("locked")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let lock_identity = LockIdentity::new(
            Digest::from_serializable(&(&workspace_id, locked, &workspace_revision)).to_string(),
        )
        .map_err(|_| TerraformCloudTransportError::Decode)?;
        let execution_mode =
            string_attribute(&attributes, "execution-mode").unwrap_or_else(|| "unknown".to_owned());
        let terraform_version = string_attribute(&attributes, "terraform-version");
        let configuration_version = string_attribute(&attributes, "current-configuration-version")
            .or_else(|| string_attribute(&attributes, "current-configuration-version-id"))
            .and_then(|value| ConfigurationVersionId::new(value).ok());
        let current_run = string_attribute(&attributes, "current-run")
            .or_else(|| string_attribute(&attributes, "current-run-id"))
            .and_then(|value| RunId::new(value).ok());
        Ok(TerraformCloudWorkspaceApiRecord {
            workspace_id,
            workspace_revision,
            lock_identity,
            locked,
            execution_mode,
            terraform_version,
            configuration_version,
            current_run,
        })
    }

    fn read_run_evidence(
        &self,
        token: &SecretMaterial,
        scope: &TerraformCloudScope,
    ) -> Result<RunEvidence, TerraformCloudTransportError> {
        let run_id = scope
            .resources
            .run
            .as_ref()
            .ok_or(TerraformCloudTransportError::InvalidConfiguration)?;
        let run_segments = ["runs", run_id.as_str()];
        let (id, attributes) = self.resource(token, &run_segments)?;
        let actual_run = RunId::new(id).map_err(|_| TerraformCloudTransportError::Decode)?;
        if actual_run != *run_id {
            return Err(TerraformCloudTransportError::Conflict);
        }
        let mode = if attributes
            .get("is-speculative")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            RunMode::Speculative
        } else {
            RunMode::Normal
        };
        let status = TerraformRunStatus::from_provider(
            string_attribute(&attributes, "status")
                .as_deref()
                .unwrap_or("unknown"),
        );
        let has_changes = attributes.get("has-changes").and_then(Value::as_bool);
        let auto_apply = attributes
            .get("auto-apply")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let observed_at = string_attribute(&attributes, "updated-at")
            .or_else(|| string_attribute(&attributes, "created-at"))
            .unwrap_or_else(|| "provider-observed".to_owned());
        let configuration_id = scope
            .resources
            .configuration_version
            .clone()
            .or_else(|| {
                string_attribute(&attributes, "configuration-version-id")
                    .and_then(|value| ConfigurationVersionId::new(value).ok())
            })
            .ok_or(TerraformCloudTransportError::InvalidConfiguration)?;
        let configuration = ConfigurationVersionFence::new(
            configuration_id.as_str(),
            ConfigurationSource::Unknown,
            configuration_id.as_str(),
            None,
            Digest::from_serializable(&("configuration-version", &configuration_id)),
        )
        .map_err(|_| TerraformCloudTransportError::Decode)?;
        let plan_id = scope.resources.plan.clone().or_else(|| {
            self.relationship_id(token, &run_segments, "plan")
                .ok()
                .flatten()
                .and_then(|value| PlanId::new(value).ok())
        });
        let plan = plan_id.map(|id| self.read_plan(token, &id, &observed_at));
        let plan = plan.transpose()?;
        let apply_id = scope.resources.apply.clone().or_else(|| {
            self.relationship_id(token, &run_segments, "apply")
                .ok()
                .flatten()
                .and_then(|value| ApplyId::new(value).ok())
        });
        let apply = apply_id.map(|id| self.read_apply(token, &id, &observed_at));
        let apply = apply.transpose()?;
        let policy_id = scope.resources.policy_evaluation.clone().or_else(|| {
            self.relationship_id(token, &run_segments, "policy-evaluations")
                .ok()
                .flatten()
                .and_then(|value| crate::PolicyEvaluationId::new(value).ok())
        });
        let policy = policy_id.map(|id| self.read_policy(token, id, &observed_at));
        let policy = policy.transpose()?;
        let cost_id = self
            .relationship_id(token, &run_segments, "cost-estimate")
            .ok()
            .flatten();
        let cost = cost_id.map(|id| self.read_cost(token, &id, &observed_at));
        let cost = cost.transpose()?;
        let transition = StatusTransition::new(None, status, observed_at.clone())
            .map_err(|_| TerraformCloudTransportError::Decode)?;
        RunEvidence::new(
            scope.clone(),
            configuration,
            actual_run,
            status,
            mode,
            has_changes,
            auto_apply,
            None,
            vec![transition],
            plan,
            apply,
            policy,
            cost,
            observed_at,
        )
        .map_err(|_| TerraformCloudTransportError::Decode)
    }
}

impl UreqTerraformCloudTransport {
    fn read_plan(
        &self,
        token: &SecretMaterial,
        id: &PlanId,
        observed_at: &str,
    ) -> Result<PlanEvidence, TerraformCloudTransportError> {
        let segments = ["plans", id.as_str()];
        let (_actual_id, attributes) = self.resource(token, &segments)?;
        let status = match string_attribute(&attributes, "status")
            .as_deref()
            .unwrap_or("unknown")
            .to_ascii_lowercase()
            .as_str()
        {
            "pending" => PlanStatus::Pending,
            "running" | "queued" => PlanStatus::Running,
            "finished" | "complete" => PlanStatus::Finished,
            "errored" | "error" => PlanStatus::Errored,
            _ => PlanStatus::ProviderUnknown,
        };
        PlanEvidence::new(
            id.clone(),
            status,
            attributes.get("has-changes").and_then(Value::as_bool),
            safe_summary_digest("plan", &id.to_string(), &attributes),
            observed_at.to_owned(),
        )
        .map_err(|_| TerraformCloudTransportError::Decode)
    }

    fn read_apply(
        &self,
        token: &SecretMaterial,
        id: &ApplyId,
        observed_at: &str,
    ) -> Result<ApplyEvidence, TerraformCloudTransportError> {
        let segments = ["applies", id.as_str()];
        let (_actual_id, attributes) = self.resource(token, &segments)?;
        let status = match string_attribute(&attributes, "status")
            .as_deref()
            .unwrap_or("unknown")
            .to_ascii_lowercase()
            .as_str()
        {
            "pending" | "queued" => crate::ApplyStatus::Pending,
            "applying" => crate::ApplyStatus::Applying,
            "finished" | "applied" => crate::ApplyStatus::Finished,
            "errored" | "error" => crate::ApplyStatus::Errored,
            "canceled" | "cancelled" => crate::ApplyStatus::Canceled,
            _ => crate::ApplyStatus::ProviderUnknown,
        };
        ApplyEvidence::new(
            id.clone(),
            status,
            Some(safe_summary_digest("apply", &id.to_string(), &attributes)),
            observed_at.to_owned(),
        )
        .map_err(|_| TerraformCloudTransportError::Decode)
    }

    fn read_policy(
        &self,
        token: &SecretMaterial,
        id: crate::PolicyEvaluationId,
        observed_at: &str,
    ) -> Result<PolicyEvidence, TerraformCloudTransportError> {
        let segments = ["policy-evaluations", id.as_str()];
        let (_actual_id, attributes) = self.resource(token, &segments)?;
        let result = match string_attribute(&attributes, "result")
            .or_else(|| string_attribute(&attributes, "status"))
            .unwrap_or_else(|| "unknown".to_owned())
            .to_ascii_lowercase()
            .as_str()
        {
            "passed" | "pass" => PolicyResult::Passed,
            "failed" | "fail" => PolicyResult::Failed,
            "override_required" | "overridden" => PolicyResult::OverrideRequired,
            "not_evaluated" => PolicyResult::NotEvaluated,
            _ => PolicyResult::ProviderUnknown,
        };
        let policy_set_id = string_attribute(&attributes, "policy-set-id")
            .and_then(|value| PolicySetId::new(value).ok());
        PolicyEvidence::new(
            id,
            policy_set_id,
            result,
            safe_summary_digest("policy", &attributes_to_identity(&attributes), &attributes),
            observed_at.to_owned(),
        )
        .map_err(|_| TerraformCloudTransportError::Decode)
    }

    fn read_cost(
        &self,
        token: &SecretMaterial,
        id: &str,
        observed_at: &str,
    ) -> Result<CostEvidence, TerraformCloudTransportError> {
        let segments = ["cost-estimates", id];
        let (_actual_id, attributes) = self.resource(token, &segments)?;
        let availability = match string_attribute(&attributes, "status")
            .unwrap_or_else(|| "unknown".to_owned())
            .to_ascii_lowercase()
            .as_str()
        {
            "finished" | "available" | "complete" => CostAvailability::Available,
            "partial" | "incomplete" => CostAvailability::Partial,
            "pending" | "unavailable" => CostAvailability::Unavailable,
            _ => CostAvailability::ProviderUnknown,
        };
        let estimate_id = (id.len() <= crate::MAX_IDENTIFIER_BYTES).then_some(id.to_owned());
        let summary_digest = (availability != CostAvailability::Unavailable
            && availability != CostAvailability::ProviderUnknown)
            .then(|| safe_summary_digest("cost", id, &attributes));
        CostEvidence::new(
            estimate_id,
            availability,
            summary_digest,
            observed_at.to_owned(),
        )
        .map_err(|_| TerraformCloudTransportError::Decode)
    }
}

fn string_attribute(attributes: &Map<String, Value>, key: &str) -> Option<String> {
    attributes
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= crate::MAX_SOURCE_BYTES)
        .map(ToOwned::to_owned)
}

fn attributes_to_identity(attributes: &Map<String, Value>) -> String {
    attributes
        .get("id")
        .and_then(Value::as_str)
        .map_or_else(|| "provider-policy".to_owned(), ToOwned::to_owned)
}

fn safe_summary_digest(label: &str, id: &str, attributes: &Map<String, Value>) -> Digest {
    let mut safe = BTreeMap::new();
    for key in [
        "status",
        "has-changes",
        "created-at",
        "updated-at",
        "finished-at",
        "resource-additions",
        "resource-changes",
        "resource-destructions",
        "proposed-monthly-cost",
        "monthly-cost",
        "result",
    ] {
        if let Some(value) = attributes.get(key) {
            safe.insert(key, value.clone());
        }
    }
    Digest::from_serializable(&(label, id, safe))
}

fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

fn is_retryable(error: &TerraformCloudTransportError) -> bool {
    matches!(
        error,
        TerraformCloudTransportError::RateLimited { .. }
            | TerraformCloudTransportError::ServerUnavailable
            | TerraformCloudTransportError::Timeout
    )
}

fn classify_http_error(error: &ureq::Error) -> TerraformCloudTransportError {
    match error {
        ureq::Error::StatusCode(401) => TerraformCloudTransportError::Unauthorized,
        ureq::Error::StatusCode(404) => TerraformCloudTransportError::NotFoundOrUnauthorized,
        ureq::Error::StatusCode(409) => TerraformCloudTransportError::Conflict,
        ureq::Error::StatusCode(422) => TerraformCloudTransportError::UnprocessableEntity,
        ureq::Error::StatusCode(429) => TerraformCloudTransportError::RateLimited {
            retry_after_seconds: None,
        },
        ureq::Error::StatusCode(status) if *status >= 500 => {
            TerraformCloudTransportError::ServerUnavailable
        }
        _ => TerraformCloudTransportError::Network,
    }
}

// Keep the public type names easy to discover for callers that use the API
// vocabulary from the issue text.
pub type TerraformCloudRunApiTransport = UreqTerraformCloudTransport;
pub type TerraformCloudRecordingTransport = RecordingTerraformCloudTransport;
