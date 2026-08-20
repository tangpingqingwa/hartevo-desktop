use std::{
    collections::{BTreeMap, VecDeque},
    fmt,
};

use serde::Serialize;

use crate::error::{
    GcpMonitoringAlertError, GcpMonitoringTransportError, Result, TransportErrorKind,
};
use crate::model::{
    AlertId, AlertPolicyId, AlertPolicyProjection, AlertProjection, AlertState, AlertStateFilter,
    BoundedReadLimits, Digest, GcpMonitoringAlertScope, GoogleAuthKind, OpaquePageToken,
    PermissionEvidence, ProjectId, Revision, SecretReference, SeverityFilter,
};
use crate::{BLOCKED_ENV, CONTRACT_SCHEMA, MAX_PAGE_SIZE, PROVIDER_API_REVISION, PROVIDER_ID};

pub type TransportError = GcpMonitoringTransportError;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
    pub const fn connected(self) -> bool {
        false
    }

    pub const fn native(self) -> bool {
        false
    }

    pub const fn first_party(self) -> bool {
        false
    }

    pub const fn is_blocked_env(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Debug, Eq, thiserror::Error, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("provider version is empty")]
    EmptyVersion,
    #[error("Layer 1 cannot register a native or connected provider")]
    NativeProviderForbidden,
    #[error("provider identity is invalid")]
    InvalidIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpMonitoringProviderDefinition {
    pub schema_version: String,
    pub provider_id: String,
    pub provider_version: String,
    pub api_revision: String,
    pub capability_digest: Digest,
    pub provenance: ProviderProvenance,
    pub list_alert_policies: bool,
    pub get_alert_policy: bool,
    pub list_alerts: bool,
    pub get_alert: bool,
    pub live_execution: bool,
    pub connected: bool,
    pub native: bool,
    pub external_writes: bool,
}

impl GcpMonitoringProviderDefinition {
    pub fn new(
        provider_version: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> std::result::Result<Self, ProviderDefinitionError> {
        let provider_version = provider_version.into();
        if provider_version.is_empty() {
            return Err(ProviderDefinitionError::EmptyVersion);
        }
        if provenance.native() || provenance.connected() {
            return Err(ProviderDefinitionError::NativeProviderForbidden);
        }
        let capability_digest = Digest::from_parts(
            "gcp-monitoring-provider-capability/v1",
            &[
                ("schema", CONTRACT_SCHEMA.to_owned()),
                ("provider", PROVIDER_ID.to_owned()),
                ("version", provider_version.clone()),
                ("api", PROVIDER_API_REVISION.to_owned()),
                ("provenance", format!("{provenance:?}")),
                (
                    "operations",
                    "alertPolicies.list,alertPolicies.get,alerts.list,alerts.get".to_owned(),
                ),
                ("live-execution", "false".to_owned()),
                ("external-writes", "false".to_owned()),
            ],
        );
        Ok(Self {
            schema_version: CONTRACT_SCHEMA.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            provider_version,
            api_revision: PROVIDER_API_REVISION.to_owned(),
            capability_digest,
            provenance,
            list_alert_policies: true,
            get_alert_policy: true,
            list_alerts: true,
            get_alert: true,
            live_execution: false,
            connected: false,
            native: false,
            external_writes: false,
        })
    }

    pub fn provider_digest(&self) -> Digest {
        Digest::from_parts(
            "gcp-monitoring-provider-definition/v1",
            &[
                ("schema", self.schema_version.clone()),
                ("id", self.provider_id.clone()),
                ("version", self.provider_version.clone()),
                ("api", self.api_revision.clone()),
                ("capability", self.capability_digest.as_str().to_owned()),
                ("provenance", format!("{:?}", self.provenance)),
                ("list-policies", self.list_alert_policies.to_string()),
                ("get-policy", self.get_alert_policy.to_string()),
                ("list-alerts", self.list_alerts.to_string()),
                ("get-alert", self.get_alert.to_string()),
                ("live", self.live_execution.to_string()),
                ("connected", self.connected.to_string()),
                ("native", self.native.to_string()),
                ("writes", self.external_writes.to_string()),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertOperation {
    ListAlertPolicies,
    GetAlertPolicy,
    ListAlerts,
    GetAlert,
}

impl AlertOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ListAlertPolicies => "alertPolicies.list",
            Self::GetAlertPolicy => "alertPolicies.get",
            Self::ListAlerts => "alerts.list",
            Self::GetAlert => "alerts.get",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: AlertOperation,
    pub request_digest: Digest,
    pub path_digest: Digest,
    pub scope_digest: Digest,
    pub metrics_scope_digest: Digest,
    pub project_digest: Digest,
    pub page_token_digest: Option<Digest>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ListAlertPoliciesRequest {
    pub project_id: ProjectId,
    pub metrics_scope_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub mission_revision: Revision,
    pub project_revision: Revision,
    pub secret_reference_digest: Digest,
    pub credential_revision: Revision,
    pub auth_kind: GoogleAuthKind,
    pub page_size: u16,
    pub page_token: Option<OpaquePageToken>,
    pub request_digest: Digest,
}

impl fmt::Debug for ListAlertPoliciesRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListAlertPoliciesRequest")
            .field("project_id", &self.project_id)
            .field("metrics_scope_digest", &self.metrics_scope_digest)
            .field("scope_digest", &self.scope_digest)
            .field("page_size", &self.page_size)
            .field(
                "page_token_digest",
                &self.page_token.as_ref().map(OpaquePageToken::digest),
            )
            .field("request_digest", &self.request_digest)
            .finish_non_exhaustive()
    }
}

impl ListAlertPoliciesRequest {
    pub fn for_scope(
        scope: &GcpMonitoringAlertScope,
        secret: &SecretReference,
        page_size: u16,
        page_token: Option<OpaquePageToken>,
    ) -> Result<Self> {
        if secret.scope_digest() != &scope.scope_digest()
            || page_size == 0
            || page_size > MAX_PAGE_SIZE
        {
            return Err(GcpMonitoringAlertError::FenceMismatch);
        }
        let request_digest = Digest::from_parts(
            "gcp-monitoring-list-alert-policies-request/v1",
            &[
                ("project", scope.project_id().as_str().to_owned()),
                ("metrics", scope.metrics_scope.digest().as_str().to_owned()),
                ("scope", scope.scope_digest().as_str().to_owned()),
                ("permission", scope.permission_digest().as_str().to_owned()),
                ("consent", scope.consent_digest().as_str().to_owned()),
                (
                    "mission-revision",
                    scope.mission_revision().get().to_string(),
                ),
                (
                    "project-revision",
                    scope.project_revision().get().to_string(),
                ),
                ("secret", secret.reference_digest().as_str().to_owned()),
                (
                    "credential-revision",
                    secret.credential_revision().get().to_string(),
                ),
                ("auth", format!("{:?}", secret.auth_kind())),
                ("page-size", page_size.to_string()),
                (
                    "page-token",
                    page_token
                        .as_ref()
                        .map_or_else(String::new, |token| token.digest().as_str().to_owned()),
                ),
            ],
        );
        Ok(Self {
            project_id: scope.project.project_id.clone(),
            metrics_scope_digest: scope.metrics_scope.digest().clone(),
            scope_digest: scope.scope_digest(),
            permission_digest: scope.permission_digest().clone(),
            consent_digest: scope.consent_digest().clone(),
            mission_revision: scope.mission_revision(),
            project_revision: scope.project_revision(),
            secret_reference_digest: secret.reference_digest().clone(),
            credential_revision: secret.credential_revision(),
            auth_kind: secret.auth_kind(),
            page_size,
            page_token,
            request_digest,
        })
    }

    pub fn page_token_digest(&self) -> Option<Digest> {
        self.page_token.as_ref().map(OpaquePageToken::digest)
    }

    pub fn path(&self) -> String {
        format!("projects/{}/alertPolicies", self.project_id.as_str())
    }

    fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AlertOperation::ListAlertPolicies,
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path()),
            scope_digest: self.scope_digest.clone(),
            metrics_scope_digest: self.metrics_scope_digest.clone(),
            project_digest: self.project_id.digest(),
            page_token_digest: self.page_token_digest(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetAlertPolicyRequest {
    pub project_id: ProjectId,
    pub policy_id: AlertPolicyId,
    pub metrics_scope_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub mission_revision: Revision,
    pub project_revision: Revision,
    pub secret_reference_digest: Digest,
    pub credential_revision: Revision,
    pub auth_kind: GoogleAuthKind,
    pub request_digest: Digest,
}

impl GetAlertPolicyRequest {
    pub fn for_scope(
        scope: &GcpMonitoringAlertScope,
        secret: &SecretReference,
        policy_id: AlertPolicyId,
    ) -> Result<Self> {
        if !scope.policy.contains(&policy_id) {
            return Err(GcpMonitoringAlertError::PolicyOrAlertOutOfScope);
        }
        if secret.scope_digest() != &scope.scope_digest() {
            return Err(GcpMonitoringAlertError::FenceMismatch);
        }
        let request_digest = Digest::from_parts(
            "gcp-monitoring-get-alert-policy-request/v1",
            &[
                ("project", scope.project_id().as_str().to_owned()),
                ("policy", policy_id.as_str().to_owned()),
                ("metrics", scope.metrics_scope.digest().as_str().to_owned()),
                ("scope", scope.scope_digest().as_str().to_owned()),
                ("permission", scope.permission_digest().as_str().to_owned()),
                ("consent", scope.consent_digest().as_str().to_owned()),
                (
                    "mission-revision",
                    scope.mission_revision().get().to_string(),
                ),
                (
                    "project-revision",
                    scope.project_revision().get().to_string(),
                ),
                ("secret", secret.reference_digest().as_str().to_owned()),
                (
                    "credential-revision",
                    secret.credential_revision().get().to_string(),
                ),
                ("auth", format!("{:?}", secret.auth_kind())),
            ],
        );
        Ok(Self {
            project_id: scope.project.project_id.clone(),
            policy_id,
            metrics_scope_digest: scope.metrics_scope.digest().clone(),
            scope_digest: scope.scope_digest(),
            permission_digest: scope.permission_digest().clone(),
            consent_digest: scope.consent_digest().clone(),
            mission_revision: scope.mission_revision(),
            project_revision: scope.project_revision(),
            secret_reference_digest: secret.reference_digest().clone(),
            credential_revision: secret.credential_revision(),
            auth_kind: secret.auth_kind(),
            request_digest,
        })
    }

    pub fn path(&self) -> String {
        format!(
            "projects/{}/alertPolicies/{}",
            self.project_id.as_str(),
            self.policy_id.as_str()
        )
    }

    fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AlertOperation::GetAlertPolicy,
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path()),
            scope_digest: self.scope_digest.clone(),
            metrics_scope_digest: self.metrics_scope_digest.clone(),
            project_digest: self.project_id.digest(),
            page_token_digest: None,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ListAlertsRequest {
    pub project_id: ProjectId,
    pub metrics_scope_digest: Digest,
    pub policy_scope_digest: Digest,
    pub alert_scope_digest: Digest,
    pub resource_scope_digest: Digest,
    pub scope_digest: Digest,
    pub state_filter: AlertStateFilter,
    pub severity_filter: SeverityFilter,
    pub page_size: u16,
    pub page_token: Option<OpaquePageToken>,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub mission_revision: Revision,
    pub project_revision: Revision,
    pub secret_reference_digest: Digest,
    pub credential_revision: Revision,
    pub auth_kind: GoogleAuthKind,
    pub request_digest: Digest,
}

impl fmt::Debug for ListAlertsRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListAlertsRequest")
            .field("project_id", &self.project_id)
            .field("metrics_scope_digest", &self.metrics_scope_digest)
            .field("policy_scope_digest", &self.policy_scope_digest)
            .field("alert_scope_digest", &self.alert_scope_digest)
            .field("resource_scope_digest", &self.resource_scope_digest)
            .field("state_filter", &self.state_filter)
            .field("severity_filter", &self.severity_filter)
            .field("page_size", &self.page_size)
            .field(
                "page_token_digest",
                &self.page_token.as_ref().map(OpaquePageToken::digest),
            )
            .field("request_digest", &self.request_digest)
            .finish_non_exhaustive()
    }
}

impl ListAlertsRequest {
    pub fn for_scope(
        scope: &GcpMonitoringAlertScope,
        secret: &SecretReference,
        page_size: u16,
        page_token: Option<OpaquePageToken>,
    ) -> Result<Self> {
        if secret.scope_digest() != &scope.scope_digest()
            || page_size == 0
            || page_size > MAX_PAGE_SIZE
        {
            return Err(GcpMonitoringAlertError::FenceMismatch);
        }
        let request_digest = Digest::from_parts(
            "gcp-monitoring-list-alerts-request/v1",
            &[
                ("project", scope.project_id().as_str().to_owned()),
                ("metrics", scope.metrics_scope.digest().as_str().to_owned()),
                ("policy-scope", scope.policy.digest().as_str().to_owned()),
                ("alert-scope", scope.alert.digest().as_str().to_owned()),
                (
                    "resource-scope",
                    scope.resource.digest().as_str().to_owned(),
                ),
                ("scope", scope.scope_digest().as_str().to_owned()),
                ("state", format!("{:?}", scope.alert.state_filter)),
                ("severity", format!("{:?}", scope.alert.severity_filter)),
                ("permission", scope.permission_digest().as_str().to_owned()),
                ("consent", scope.consent_digest().as_str().to_owned()),
                (
                    "mission-revision",
                    scope.mission_revision().get().to_string(),
                ),
                (
                    "project-revision",
                    scope.project_revision().get().to_string(),
                ),
                ("secret", secret.reference_digest().as_str().to_owned()),
                (
                    "credential-revision",
                    secret.credential_revision().get().to_string(),
                ),
                ("auth", format!("{:?}", secret.auth_kind())),
                ("page-size", page_size.to_string()),
                (
                    "page-token",
                    page_token
                        .as_ref()
                        .map_or_else(String::new, |token| token.digest().as_str().to_owned()),
                ),
            ],
        );
        Ok(Self {
            project_id: scope.project.project_id.clone(),
            metrics_scope_digest: scope.metrics_scope.digest().clone(),
            policy_scope_digest: scope.policy.digest().clone(),
            alert_scope_digest: scope.alert.digest().clone(),
            resource_scope_digest: scope.resource.digest().clone(),
            scope_digest: scope.scope_digest(),
            state_filter: scope.alert.state_filter,
            severity_filter: scope.alert.severity_filter,
            page_size,
            page_token,
            permission_digest: scope.permission_digest().clone(),
            consent_digest: scope.consent_digest().clone(),
            mission_revision: scope.mission_revision(),
            project_revision: scope.project_revision(),
            secret_reference_digest: secret.reference_digest().clone(),
            credential_revision: secret.credential_revision(),
            auth_kind: secret.auth_kind(),
            request_digest,
        })
    }

    pub fn page_token_digest(&self) -> Option<Digest> {
        self.page_token.as_ref().map(OpaquePageToken::digest)
    }

    pub fn path(&self) -> String {
        format!("projects/{}/alerts", self.project_id.as_str())
    }

    fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AlertOperation::ListAlerts,
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path()),
            scope_digest: self.scope_digest.clone(),
            metrics_scope_digest: self.metrics_scope_digest.clone(),
            project_digest: self.project_id.digest(),
            page_token_digest: self.page_token_digest(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetAlertRequest {
    pub project_id: ProjectId,
    pub alert_id: AlertId,
    pub metrics_scope_digest: Digest,
    pub policy_scope_digest: Digest,
    pub alert_scope_digest: Digest,
    pub resource_scope_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub mission_revision: Revision,
    pub project_revision: Revision,
    pub secret_reference_digest: Digest,
    pub credential_revision: Revision,
    pub auth_kind: GoogleAuthKind,
    pub request_digest: Digest,
}

impl GetAlertRequest {
    pub fn for_scope(
        scope: &GcpMonitoringAlertScope,
        secret: &SecretReference,
        alert_id: AlertId,
    ) -> Result<Self> {
        if !scope.alert.contains(&alert_id) || secret.scope_digest() != &scope.scope_digest() {
            return Err(GcpMonitoringAlertError::PolicyOrAlertOutOfScope);
        }
        let request_digest = Digest::from_parts(
            "gcp-monitoring-get-alert-request/v1",
            &[
                ("project", scope.project_id().as_str().to_owned()),
                ("alert", alert_id.as_str().to_owned()),
                ("metrics", scope.metrics_scope.digest().as_str().to_owned()),
                ("policy-scope", scope.policy.digest().as_str().to_owned()),
                ("alert-scope", scope.alert.digest().as_str().to_owned()),
                (
                    "resource-scope",
                    scope.resource.digest().as_str().to_owned(),
                ),
                ("scope", scope.scope_digest().as_str().to_owned()),
                ("permission", scope.permission_digest().as_str().to_owned()),
                ("consent", scope.consent_digest().as_str().to_owned()),
                (
                    "mission-revision",
                    scope.mission_revision().get().to_string(),
                ),
                (
                    "project-revision",
                    scope.project_revision().get().to_string(),
                ),
                ("secret", secret.reference_digest().as_str().to_owned()),
                (
                    "credential-revision",
                    secret.credential_revision().get().to_string(),
                ),
                ("auth", format!("{:?}", secret.auth_kind())),
            ],
        );
        Ok(Self {
            project_id: scope.project.project_id.clone(),
            alert_id,
            metrics_scope_digest: scope.metrics_scope.digest().clone(),
            policy_scope_digest: scope.policy.digest().clone(),
            alert_scope_digest: scope.alert.digest().clone(),
            resource_scope_digest: scope.resource.digest().clone(),
            scope_digest: scope.scope_digest(),
            permission_digest: scope.permission_digest().clone(),
            consent_digest: scope.consent_digest().clone(),
            mission_revision: scope.mission_revision(),
            project_revision: scope.project_revision(),
            secret_reference_digest: secret.reference_digest().clone(),
            credential_revision: secret.credential_revision(),
            auth_kind: secret.auth_kind(),
            request_digest,
        })
    }

    pub fn path(&self) -> String {
        format!(
            "projects/{}/alerts/{}",
            self.project_id.as_str(),
            self.alert_id.as_str()
        )
    }

    fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AlertOperation::GetAlert,
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path()),
            scope_digest: self.scope_digest.clone(),
            metrics_scope_digest: self.metrics_scope_digest.clone(),
            project_digest: self.project_id.digest(),
            page_token_digest: None,
        }
    }
}

#[allow(clippy::struct_field_names)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct ResponseFence {
    observed_scope_digest: Digest,
    observed_permission_digest: Digest,
    observed_consent_digest: Digest,
    observed_mission_revision: Revision,
    observed_project_revision: Revision,
    observed_credential_revision: Revision,
}

impl ResponseFence {
    fn from_request(request: &impl RequestFence) -> Self {
        Self {
            observed_scope_digest: request.scope_digest().clone(),
            observed_permission_digest: request.permission_digest().clone(),
            observed_consent_digest: request.consent_digest().clone(),
            observed_mission_revision: request.mission_revision(),
            observed_project_revision: request.project_revision(),
            observed_credential_revision: request.credential_revision(),
        }
    }

    fn digest(&self) -> Digest {
        Digest::from_parts(
            "gcp-monitoring-response-fence/v1",
            &[
                ("scope", self.observed_scope_digest.as_str().to_owned()),
                (
                    "permission",
                    self.observed_permission_digest.as_str().to_owned(),
                ),
                ("consent", self.observed_consent_digest.as_str().to_owned()),
                ("mission", self.observed_mission_revision.get().to_string()),
                ("project", self.observed_project_revision.get().to_string()),
                (
                    "credential",
                    self.observed_credential_revision.get().to_string(),
                ),
            ],
        )
    }
}

trait RequestFence {
    fn scope_digest(&self) -> &Digest;
    fn permission_digest(&self) -> &Digest;
    fn consent_digest(&self) -> &Digest;
    fn mission_revision(&self) -> Revision;
    fn project_revision(&self) -> Revision;
    fn credential_revision(&self) -> Revision;
}

macro_rules! impl_request_fence {
    ($type:ty) => {
        impl RequestFence for $type {
            fn scope_digest(&self) -> &Digest {
                &self.scope_digest
            }
            fn permission_digest(&self) -> &Digest {
                &self.permission_digest
            }
            fn consent_digest(&self) -> &Digest {
                &self.consent_digest
            }
            fn mission_revision(&self) -> Revision {
                self.mission_revision
            }
            fn project_revision(&self) -> Revision {
                self.project_revision
            }
            fn credential_revision(&self) -> Revision {
                self.credential_revision
            }
        }
    };
}

impl_request_fence!(ListAlertPoliciesRequest);
impl_request_fence!(GetAlertPolicyRequest);
impl_request_fence!(ListAlertsRequest);
impl_request_fence!(GetAlertRequest);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListAlertPoliciesResponse {
    pub policies: Vec<AlertPolicyProjection>,
    pub next_page_token: Option<OpaquePageToken>,
    pub total_size: u64,
    pub response_bytes: u64,
    pub request_digest: Digest,
    pub observed_scope_digest: Digest,
    pub observed_permission_digest: Digest,
    pub observed_consent_digest: Digest,
    pub observed_mission_revision: Revision,
    pub observed_project_revision: Revision,
    pub observed_credential_revision: Revision,
    pub provider_provenance: ProviderProvenance,
    pub response_digest: Digest,
}

impl ListAlertPoliciesResponse {
    pub fn new(
        request: &ListAlertPoliciesRequest,
        policies: Vec<AlertPolicyProjection>,
        next_page_token: Option<OpaquePageToken>,
        total_size: u64,
        response_bytes: u64,
        provider_provenance: ProviderProvenance,
    ) -> Result<Self> {
        if policies.len() > usize::from(request.page_size)
            || response_bytes > crate::MAX_RESPONSE_BYTES
        {
            return Err(GcpMonitoringAlertError::InvalidResponseShape);
        }
        for policy in &policies {
            policy.validate()?;
        }
        let fence = ResponseFence::from_request(request);
        let response_digest = response_digest(
            "gcp-monitoring-list-alert-policies-response/v1",
            &fence,
            &request.request_digest,
            &policies
                .iter()
                .map(|policy| policy.policy_digest.as_str())
                .collect::<Vec<_>>()
                .join(","),
            next_page_token.as_ref(),
            total_size,
            response_bytes,
        );
        Ok(Self {
            policies,
            next_page_token,
            total_size,
            response_bytes,
            request_digest: request.request_digest.clone(),
            observed_scope_digest: fence.observed_scope_digest,
            observed_permission_digest: fence.observed_permission_digest,
            observed_consent_digest: fence.observed_consent_digest,
            observed_mission_revision: fence.observed_mission_revision,
            observed_project_revision: fence.observed_project_revision,
            observed_credential_revision: fence.observed_credential_revision,
            provider_provenance,
            response_digest,
        })
    }

    pub fn validate_digest(&self) -> Result<()> {
        let fence = self.response_fence();
        let expected = response_digest(
            "gcp-monitoring-list-alert-policies-response/v1",
            &fence,
            &self.request_digest,
            &self
                .policies
                .iter()
                .map(|policy| policy.policy_digest.as_str())
                .collect::<Vec<_>>()
                .join(","),
            self.next_page_token.as_ref(),
            self.total_size,
            self.response_bytes,
        );
        if expected != self.response_digest {
            Err(GcpMonitoringAlertError::TamperedEvidence)
        } else {
            Ok(())
        }
    }

    fn response_fence(&self) -> ResponseFence {
        ResponseFence {
            observed_scope_digest: self.observed_scope_digest.clone(),
            observed_permission_digest: self.observed_permission_digest.clone(),
            observed_consent_digest: self.observed_consent_digest.clone(),
            observed_mission_revision: self.observed_mission_revision,
            observed_project_revision: self.observed_project_revision,
            observed_credential_revision: self.observed_credential_revision,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetAlertPolicyResponse {
    pub policy: AlertPolicyProjection,
    pub response_bytes: u64,
    pub request_digest: Digest,
    pub observed_scope_digest: Digest,
    pub observed_permission_digest: Digest,
    pub observed_consent_digest: Digest,
    pub observed_mission_revision: Revision,
    pub observed_project_revision: Revision,
    pub observed_credential_revision: Revision,
    pub provider_provenance: ProviderProvenance,
    pub response_digest: Digest,
}

impl GetAlertPolicyResponse {
    pub fn new(
        request: &GetAlertPolicyRequest,
        policy: AlertPolicyProjection,
        response_bytes: u64,
        provider_provenance: ProviderProvenance,
    ) -> Result<Self> {
        if response_bytes > crate::MAX_RESPONSE_BYTES {
            return Err(GcpMonitoringAlertError::InvalidResponseShape);
        }
        policy.validate()?;
        let fence = ResponseFence::from_request(request);
        let response_digest = response_digest(
            "gcp-monitoring-get-alert-policy-response/v1",
            &fence,
            &request.request_digest,
            policy.policy_digest.as_str(),
            None,
            1,
            response_bytes,
        );
        Ok(Self {
            policy,
            response_bytes,
            request_digest: request.request_digest.clone(),
            observed_scope_digest: fence.observed_scope_digest,
            observed_permission_digest: fence.observed_permission_digest,
            observed_consent_digest: fence.observed_consent_digest,
            observed_mission_revision: fence.observed_mission_revision,
            observed_project_revision: fence.observed_project_revision,
            observed_credential_revision: fence.observed_credential_revision,
            provider_provenance,
            response_digest,
        })
    }

    pub fn validate_digest(&self) -> Result<()> {
        let expected = response_digest(
            "gcp-monitoring-get-alert-policy-response/v1",
            &self.response_fence(),
            &self.request_digest,
            self.policy.policy_digest.as_str(),
            None,
            1,
            self.response_bytes,
        );
        if expected != self.response_digest {
            Err(GcpMonitoringAlertError::TamperedEvidence)
        } else {
            Ok(())
        }
    }

    fn response_fence(&self) -> ResponseFence {
        ResponseFence {
            observed_scope_digest: self.observed_scope_digest.clone(),
            observed_permission_digest: self.observed_permission_digest.clone(),
            observed_consent_digest: self.observed_consent_digest.clone(),
            observed_mission_revision: self.observed_mission_revision,
            observed_project_revision: self.observed_project_revision,
            observed_credential_revision: self.observed_credential_revision,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListAlertsResponse {
    pub alerts: Vec<AlertProjection>,
    pub next_page_token: Option<OpaquePageToken>,
    pub total_size: u64,
    pub response_bytes: u64,
    pub request_digest: Digest,
    pub observed_scope_digest: Digest,
    pub observed_permission_digest: Digest,
    pub observed_consent_digest: Digest,
    pub observed_mission_revision: Revision,
    pub observed_project_revision: Revision,
    pub observed_credential_revision: Revision,
    pub provider_provenance: ProviderProvenance,
    pub response_digest: Digest,
}

impl ListAlertsResponse {
    pub fn new(
        request: &ListAlertsRequest,
        alerts: Vec<AlertProjection>,
        next_page_token: Option<OpaquePageToken>,
        total_size: u64,
        response_bytes: u64,
        provider_provenance: ProviderProvenance,
    ) -> Result<Self> {
        if alerts.len() > usize::from(request.page_size)
            || response_bytes > crate::MAX_RESPONSE_BYTES
        {
            return Err(GcpMonitoringAlertError::InvalidResponseShape);
        }
        for alert in &alerts {
            alert.validate()?;
        }
        let fence = ResponseFence::from_request(request);
        let response_digest = response_digest(
            "gcp-monitoring-list-alerts-response/v1",
            &fence,
            &request.request_digest,
            &alerts
                .iter()
                .map(|alert| alert.alert_digest.as_str())
                .collect::<Vec<_>>()
                .join(","),
            next_page_token.as_ref(),
            total_size,
            response_bytes,
        );
        Ok(Self {
            alerts,
            next_page_token,
            total_size,
            response_bytes,
            request_digest: request.request_digest.clone(),
            observed_scope_digest: fence.observed_scope_digest,
            observed_permission_digest: fence.observed_permission_digest,
            observed_consent_digest: fence.observed_consent_digest,
            observed_mission_revision: fence.observed_mission_revision,
            observed_project_revision: fence.observed_project_revision,
            observed_credential_revision: fence.observed_credential_revision,
            provider_provenance,
            response_digest,
        })
    }

    pub fn validate_digest(&self) -> Result<()> {
        let expected = response_digest(
            "gcp-monitoring-list-alerts-response/v1",
            &self.response_fence(),
            &self.request_digest,
            &self
                .alerts
                .iter()
                .map(|alert| alert.alert_digest.as_str())
                .collect::<Vec<_>>()
                .join(","),
            self.next_page_token.as_ref(),
            self.total_size,
            self.response_bytes,
        );
        if expected != self.response_digest {
            Err(GcpMonitoringAlertError::TamperedEvidence)
        } else {
            Ok(())
        }
    }

    fn response_fence(&self) -> ResponseFence {
        ResponseFence {
            observed_scope_digest: self.observed_scope_digest.clone(),
            observed_permission_digest: self.observed_permission_digest.clone(),
            observed_consent_digest: self.observed_consent_digest.clone(),
            observed_mission_revision: self.observed_mission_revision,
            observed_project_revision: self.observed_project_revision,
            observed_credential_revision: self.observed_credential_revision,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetAlertResponse {
    pub alert: AlertProjection,
    pub response_bytes: u64,
    pub request_digest: Digest,
    pub observed_scope_digest: Digest,
    pub observed_permission_digest: Digest,
    pub observed_consent_digest: Digest,
    pub observed_mission_revision: Revision,
    pub observed_project_revision: Revision,
    pub observed_credential_revision: Revision,
    pub provider_provenance: ProviderProvenance,
    pub response_digest: Digest,
}

impl GetAlertResponse {
    pub fn new(
        request: &GetAlertRequest,
        alert: AlertProjection,
        response_bytes: u64,
        provider_provenance: ProviderProvenance,
    ) -> Result<Self> {
        if response_bytes > crate::MAX_RESPONSE_BYTES {
            return Err(GcpMonitoringAlertError::InvalidResponseShape);
        }
        alert.validate()?;
        let fence = ResponseFence::from_request(request);
        let response_digest = response_digest(
            "gcp-monitoring-get-alert-response/v1",
            &fence,
            &request.request_digest,
            alert.alert_digest.as_str(),
            None,
            1,
            response_bytes,
        );
        Ok(Self {
            alert,
            response_bytes,
            request_digest: request.request_digest.clone(),
            observed_scope_digest: fence.observed_scope_digest,
            observed_permission_digest: fence.observed_permission_digest,
            observed_consent_digest: fence.observed_consent_digest,
            observed_mission_revision: fence.observed_mission_revision,
            observed_project_revision: fence.observed_project_revision,
            observed_credential_revision: fence.observed_credential_revision,
            provider_provenance,
            response_digest,
        })
    }

    pub fn validate_digest(&self) -> Result<()> {
        let expected = response_digest(
            "gcp-monitoring-get-alert-response/v1",
            &self.response_fence(),
            &self.request_digest,
            self.alert.alert_digest.as_str(),
            None,
            1,
            self.response_bytes,
        );
        if expected != self.response_digest {
            Err(GcpMonitoringAlertError::TamperedEvidence)
        } else {
            Ok(())
        }
    }

    fn response_fence(&self) -> ResponseFence {
        ResponseFence {
            observed_scope_digest: self.observed_scope_digest.clone(),
            observed_permission_digest: self.observed_permission_digest.clone(),
            observed_consent_digest: self.observed_consent_digest.clone(),
            observed_mission_revision: self.observed_mission_revision,
            observed_project_revision: self.observed_project_revision,
            observed_credential_revision: self.observed_credential_revision,
        }
    }
}

fn response_digest(
    domain: &str,
    fence: &ResponseFence,
    request_digest: &Digest,
    item_digest: &str,
    next_page_token: Option<&OpaquePageToken>,
    total_size: u64,
    response_bytes: u64,
) -> Digest {
    Digest::from_parts(
        domain,
        &[
            ("fence", fence.digest().as_str().to_owned()),
            ("request", request_digest.as_str().to_owned()),
            ("items", item_digest.to_owned()),
            (
                "next-token",
                next_page_token
                    .map_or_else(String::new, |token| token.digest().as_str().to_owned()),
            ),
            ("total", total_size.to_string()),
            ("bytes", response_bytes.to_string()),
        ],
    )
}

/// Provider seam. Implementations may replay a fixture or recording, but this
/// Layer-1 crate intentionally exposes no native HTTP or credential resolver.
pub trait GcpMonitoringTransport: fmt::Debug {
    fn provenance(&self) -> ProviderProvenance;

    fn list_alert_policies(
        &mut self,
        request: &ListAlertPoliciesRequest,
    ) -> std::result::Result<ListAlertPoliciesResponse, TransportError>;

    fn get_alert_policy(
        &mut self,
        _request: &GetAlertPolicyRequest,
    ) -> std::result::Result<GetAlertPolicyResponse, TransportError>;

    fn list_alerts(
        &mut self,
        request: &ListAlertsRequest,
    ) -> std::result::Result<ListAlertsResponse, TransportError>;

    fn get_alert(
        &mut self,
        request: &GetAlertRequest,
    ) -> std::result::Result<GetAlertResponse, TransportError>;
}

pub trait MonitoringProvider: fmt::Debug {
    fn definition(&self) -> &GcpMonitoringProviderDefinition;

    fn provenance(&self) -> ProviderProvenance {
        self.definition().provenance
    }

    fn list_alert_policies(
        &mut self,
        request: &ListAlertPoliciesRequest,
    ) -> std::result::Result<ListAlertPoliciesResponse, TransportError>;

    fn get_alert_policy(
        &mut self,
        request: &GetAlertPolicyRequest,
    ) -> std::result::Result<GetAlertPolicyResponse, TransportError>;

    fn list_alerts(
        &mut self,
        request: &ListAlertsRequest,
    ) -> std::result::Result<ListAlertsResponse, TransportError>;

    fn get_alert(
        &mut self,
        request: &GetAlertRequest,
    ) -> std::result::Result<GetAlertResponse, TransportError>;
}

#[derive(Debug)]
pub struct GcpMonitoringProvider<T> {
    transport: T,
    definition: GcpMonitoringProviderDefinition,
}

impl<T: GcpMonitoringTransport> GcpMonitoringProvider<T> {
    pub fn new(
        transport: T,
        provider_version: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> std::result::Result<Self, ProviderDefinitionError> {
        Ok(Self {
            transport,
            definition: GcpMonitoringProviderDefinition::new(provider_version, provenance)?,
        })
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }
}

impl<T: GcpMonitoringTransport> MonitoringProvider for GcpMonitoringProvider<T> {
    fn definition(&self) -> &GcpMonitoringProviderDefinition {
        &self.definition
    }

    fn list_alert_policies(
        &mut self,
        request: &ListAlertPoliciesRequest,
    ) -> std::result::Result<ListAlertPoliciesResponse, TransportError> {
        self.transport.list_alert_policies(request)
    }

    fn get_alert_policy(
        &mut self,
        request: &GetAlertPolicyRequest,
    ) -> std::result::Result<GetAlertPolicyResponse, TransportError> {
        self.transport.get_alert_policy(request)
    }

    fn list_alerts(
        &mut self,
        request: &ListAlertsRequest,
    ) -> std::result::Result<ListAlertsResponse, TransportError> {
        self.transport.list_alerts(request)
    }

    fn get_alert(
        &mut self,
        request: &GetAlertRequest,
    ) -> std::result::Result<GetAlertResponse, TransportError> {
        self.transport.get_alert(request)
    }
}

#[derive(Debug, Default)]
pub struct RecordingTransport {
    list_policy_responses: VecDeque<std::result::Result<ListAlertPoliciesResponse, TransportError>>,
    get_policy_responses: VecDeque<std::result::Result<GetAlertPolicyResponse, TransportError>>,
    list_alert_responses: VecDeque<std::result::Result<ListAlertsResponse, TransportError>>,
    get_alert_responses: VecDeque<std::result::Result<GetAlertResponse, TransportError>>,
    requests: Vec<RecordedRequest>,
}

impl RecordingTransport {
    pub fn push_list_alert_policies(
        &mut self,
        response: std::result::Result<ListAlertPoliciesResponse, TransportError>,
    ) {
        self.list_policy_responses.push_back(response);
    }

    pub fn push_get_alert_policy(
        &mut self,
        response: std::result::Result<GetAlertPolicyResponse, TransportError>,
    ) {
        self.get_policy_responses.push_back(response);
    }

    pub fn push_list_alerts(
        &mut self,
        response: std::result::Result<ListAlertsResponse, TransportError>,
    ) {
        self.list_alert_responses.push_back(response);
    }

    pub fn push_get_alert(
        &mut self,
        response: std::result::Result<GetAlertResponse, TransportError>,
    ) {
        self.get_alert_responses.push_back(response);
    }

    pub fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }

    fn missing_response() -> TransportError {
        GcpMonitoringTransportError::new(TransportErrorKind::Unknown, None, "missing-recording")
    }
}

impl GcpMonitoringTransport for RecordingTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Recording
    }

    fn list_alert_policies(
        &mut self,
        request: &ListAlertPoliciesRequest,
    ) -> std::result::Result<ListAlertPoliciesResponse, TransportError> {
        self.requests.push(request.recorded_request());
        self.list_policy_responses
            .pop_front()
            .unwrap_or_else(|| Err(Self::missing_response()))
    }

    fn get_alert_policy(
        &mut self,
        request: &GetAlertPolicyRequest,
    ) -> std::result::Result<GetAlertPolicyResponse, TransportError> {
        self.requests.push(request.recorded_request());
        self.get_policy_responses
            .pop_front()
            .unwrap_or_else(|| Err(Self::missing_response()))
    }

    fn list_alerts(
        &mut self,
        request: &ListAlertsRequest,
    ) -> std::result::Result<ListAlertsResponse, TransportError> {
        self.requests.push(request.recorded_request());
        self.list_alert_responses
            .pop_front()
            .unwrap_or_else(|| Err(Self::missing_response()))
    }

    fn get_alert(
        &mut self,
        request: &GetAlertRequest,
    ) -> std::result::Result<GetAlertResponse, TransportError> {
        self.requests.push(request.recorded_request());
        self.get_alert_responses
            .pop_front()
            .unwrap_or_else(|| Err(Self::missing_response()))
    }
}

#[derive(Debug, Default)]
pub struct BlockedEnvTransport;

impl GcpMonitoringTransport for BlockedEnvTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }

    fn list_alert_policies(
        &mut self,
        _request: &ListAlertPoliciesRequest,
    ) -> std::result::Result<ListAlertPoliciesResponse, TransportError> {
        Err(GcpMonitoringTransportError::blocked_env())
    }

    fn get_alert_policy(
        &mut self,
        _request: &GetAlertPolicyRequest,
    ) -> std::result::Result<GetAlertPolicyResponse, TransportError> {
        Err(GcpMonitoringTransportError::blocked_env())
    }

    fn list_alerts(
        &mut self,
        _request: &ListAlertsRequest,
    ) -> std::result::Result<ListAlertsResponse, TransportError> {
        Err(GcpMonitoringTransportError::blocked_env())
    }

    fn get_alert(
        &mut self,
        _request: &GetAlertRequest,
    ) -> std::result::Result<GetAlertResponse, TransportError> {
        Err(GcpMonitoringTransportError::blocked_env())
    }
}

#[derive(Debug)]
pub struct FixtureTransport {
    scope_digest: Digest,
    policies: Vec<AlertPolicyProjection>,
    alerts: Vec<AlertProjection>,
}

impl FixtureTransport {
    pub fn for_scope(scope: &GcpMonitoringAlertScope) -> Result<Self> {
        let policy_id = scope
            .policy
            .allowlisted_policy_ids
            .iter()
            .next()
            .cloned()
            .ok_or(GcpMonitoringAlertError::InvalidScope)?;
        let alert_id = scope.alert.allowlisted_alert_ids.iter().next().cloned();
        let policy_input = crate::AlertPolicyInput::new(
            policy_id.clone(),
            "fixture-policy",
            Some(true),
            crate::Severity::Warning,
            vec![crate::PolicyConditionInput::metric(
                "metric.type = \"fixture.googleapis.com/uptime\"",
                BTreeMap::from([("instance_id".to_owned(), "fixture-instance".to_owned())]),
                BTreeMap::from([("response_code".to_owned(), "500".to_owned())]),
            )?],
            1,
        )?;
        let policy = policy_input.into_projection();
        let selected_alert_id = alert_id.unwrap_or_else(|| {
            crate::AlertId::new("fixture-alert").expect("fixture alert identifier")
        });
        let alert_input = crate::AlertInput::new(
            selected_alert_id,
            AlertState::Open,
            crate::Timestamp::new("2026-01-01T00:00:00Z")?,
            None,
            policy_id,
            "fixture-policy",
            crate::Severity::Warning,
            Some((
                crate::ResourceType::new("gce_instance")?,
                BTreeMap::from([("instance_id".to_owned(), "fixture-instance".to_owned())]),
            )),
            Some((
                crate::MetricType::new("compute.googleapis.com/instance/uptime")?,
                BTreeMap::from([("instance_id".to_owned(), "fixture-instance".to_owned())]),
            )),
            BTreeMap::from([("log_label".to_owned(), "fixture-log".to_owned())]),
        )?;
        let alert = alert_input.into_projection()?;
        Ok(Self {
            scope_digest: scope.scope_digest(),
            policies: vec![policy],
            alerts: vec![alert],
        })
    }
}

impl GcpMonitoringTransport for FixtureTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Fixture
    }

    fn list_alert_policies(
        &mut self,
        request: &ListAlertPoliciesRequest,
    ) -> std::result::Result<ListAlertPoliciesResponse, TransportError> {
        if request.scope_digest != self.scope_digest {
            return Err(GcpMonitoringTransportError::new(
                TransportErrorKind::Conflict,
                Some(409),
                "fixture-scope-drift",
            ));
        }
        ListAlertPoliciesResponse::new(
            request,
            self.policies.clone(),
            None,
            self.policies.len() as u64,
            512,
            ProviderProvenance::Fixture,
        )
        .map_err(|_| GcpMonitoringTransportError::new(TransportErrorKind::Unknown, None, "fixture"))
    }

    fn get_alert_policy(
        &mut self,
        request: &GetAlertPolicyRequest,
    ) -> std::result::Result<GetAlertPolicyResponse, TransportError> {
        let Some(policy) = self
            .policies
            .iter()
            .find(|policy| policy.policy_id == request.policy_id)
            .cloned()
        else {
            return Err(GcpMonitoringTransportError::not_found());
        };
        GetAlertPolicyResponse::new(request, policy, 512, ProviderProvenance::Fixture).map_err(
            |_| GcpMonitoringTransportError::new(TransportErrorKind::Unknown, None, "fixture"),
        )
    }

    fn list_alerts(
        &mut self,
        request: &ListAlertsRequest,
    ) -> std::result::Result<ListAlertsResponse, TransportError> {
        let alerts = self
            .alerts
            .iter()
            .filter(|alert| request.state_filter.matches(alert.state))
            .filter(|alert| request.severity_filter.matches(alert.severity))
            .cloned()
            .collect::<Vec<_>>();
        ListAlertsResponse::new(
            request,
            alerts.clone(),
            None,
            alerts.len() as u64,
            512,
            ProviderProvenance::Fixture,
        )
        .map_err(|_| GcpMonitoringTransportError::new(TransportErrorKind::Unknown, None, "fixture"))
    }

    fn get_alert(
        &mut self,
        request: &GetAlertRequest,
    ) -> std::result::Result<GetAlertResponse, TransportError> {
        let Some(alert) = self
            .alerts
            .iter()
            .find(|alert| alert.alert_id == request.alert_id)
            .cloned()
        else {
            return Err(GcpMonitoringTransportError::not_found());
        };
        GetAlertResponse::new(request, alert, 512, ProviderProvenance::Fixture).map_err(|_| {
            GcpMonitoringTransportError::new(TransportErrorKind::Unknown, None, "fixture")
        })
    }
}

#[derive(Debug, Default)]
pub struct LoopbackTransport;

impl GcpMonitoringTransport for LoopbackTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Loopback
    }

    fn list_alert_policies(
        &mut self,
        request: &ListAlertPoliciesRequest,
    ) -> std::result::Result<ListAlertPoliciesResponse, TransportError> {
        ListAlertPoliciesResponse::new(
            request,
            Vec::new(),
            None,
            0,
            128,
            ProviderProvenance::Loopback,
        )
        .map_err(|_| {
            GcpMonitoringTransportError::new(TransportErrorKind::Unknown, None, "loopback")
        })
    }

    fn get_alert_policy(
        &mut self,
        _request: &GetAlertPolicyRequest,
    ) -> std::result::Result<GetAlertPolicyResponse, TransportError> {
        Err(GcpMonitoringTransportError::not_found())
    }

    fn list_alerts(
        &mut self,
        request: &ListAlertsRequest,
    ) -> std::result::Result<ListAlertsResponse, TransportError> {
        ListAlertsResponse::new(
            request,
            Vec::new(),
            None,
            0,
            128,
            ProviderProvenance::Loopback,
        )
        .map_err(|_| {
            GcpMonitoringTransportError::new(TransportErrorKind::Unknown, None, "loopback")
        })
    }

    fn get_alert(
        &mut self,
        _request: &GetAlertRequest,
    ) -> std::result::Result<GetAlertResponse, TransportError> {
        Err(GcpMonitoringTransportError::not_found())
    }
}

pub fn default_limits() -> BoundedReadLimits {
    BoundedReadLimits::default()
}

pub fn default_permissions() -> PermissionEvidence {
    PermissionEvidence::default()
}

pub fn blocked_environment() -> &'static str {
    BLOCKED_ENV
}
