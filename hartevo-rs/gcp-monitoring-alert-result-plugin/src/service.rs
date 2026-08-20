use std::{collections::BTreeSet, fmt};

use serde::Serialize;
use thiserror::Error;

use crate::error::TransportErrorKind;
use crate::error::{GcpMonitoringAlertError, Result};
use crate::model::{
    AlertPolicyProjection, AlertProjection, AlertState, BoundedReadLimits, Digest, EvidenceFence,
    GcpMonitoringAlertScope, PermissionEvidence, RegistrationState, Revision, ScopeSummary,
    SecretReference,
};
use crate::provider::{
    GcpMonitoringProviderDefinition, GetAlertPolicyRequest, GetAlertPolicyResponse,
    GetAlertRequest, GetAlertResponse, ListAlertPoliciesRequest, ListAlertPoliciesResponse,
    ListAlertsRequest, ListAlertsResponse, MonitoringProvider, ProviderProvenance, TransportError,
};
use crate::{
    CONSUMER_ID, CONTRACT_DIGEST_INPUT, CONTRACT_SCHEMA, CONTRACT_VERSION, EVIDENCE_LEVEL,
    PLUGIN_ID, PLUGIN_VERSION, PROVIDER_API_REVISION, PROVIDER_ID, SERVICE_ID,
};

const MAX_RETRY_ATTEMPTS: u8 = 3;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum GcpMonitoringAlertServiceError {
    #[error("registration is reversed")]
    RegistrationReversed,
    #[error("secret reference is revoked")]
    SecretRevoked,
    #[error("scope or secret reference does not match")]
    ScopeMismatch,
    #[error("provider response fence does not match the request")]
    FenceMismatch,
    #[error("provider evidence is tampered")]
    TamperedEvidence,
    #[error("provider returned a policy or alert outside the exact scope")]
    OutOfScope,
    #[error("provider returned a different policy or alert identity")]
    IdentityMismatch,
    #[error("alert policy snapshot does not match the policy scope")]
    PolicyAlertMismatch,
    #[error("provider returned a repeated page token")]
    PaginationLoop,
    #[error("provider returned an invalid response shape")]
    InvalidResponseShape,
    #[error("registration transition failed")]
    RegistrationTransition,
    #[error(transparent)]
    Model(#[from] GcpMonitoringAlertError),
    #[error("provider definition is invalid")]
    ProviderDefinition,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Reversed,
}

impl From<RegistrationState> for RegistrationStatus {
    fn from(value: RegistrationState) -> Self {
        match value {
            RegistrationState::Active => Self::Active,
            RegistrationState::Reversed => Self::Reversed,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationTransitionEvidence {
    pub from: RegistrationStatus,
    pub to: RegistrationStatus,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub revision: Revision,
    pub transition_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpMonitoringAlertRegistration {
    pub schema_version: String,
    pub contract_version: String,
    pub plugin_id: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub plugin_version: String,
    pub api_revision: String,
    pub provider_version: String,
    pub contract_digest: Digest,
    pub api_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub evidence_digest: Digest,
    pub secret_reference_digest: Digest,
    pub revision: Revision,
    pub registration_digest: Digest,
    pub state: RegistrationState,
}

impl GcpMonitoringAlertRegistration {
    pub fn new(
        scope: &GcpMonitoringAlertScope,
        secret: &SecretReference,
        provider: &GcpMonitoringProviderDefinition,
    ) -> std::result::Result<Self, GcpMonitoringAlertServiceError> {
        if secret.scope_digest() != &scope.scope_digest() || provider.native || provider.connected {
            return Err(GcpMonitoringAlertServiceError::ScopeMismatch);
        }
        let contract_digest = Digest::from_text(CONTRACT_DIGEST_INPUT);
        let api_digest = Digest::from_parts(
            "gcp-monitoring-api/v1",
            &[("revision", PROVIDER_API_REVISION.to_owned())],
        );
        let evidence_digest = evidence_shape_digest();
        let registration_digest = registration_digest(
            &contract_digest,
            &api_digest,
            &provider.provider_digest(),
            scope.permission_digest(),
            &scope.scope_digest(),
            &evidence_digest,
            secret.reference_digest(),
            Revision::new(1).map_err(GcpMonitoringAlertServiceError::Model)?,
        );
        Ok(Self {
            schema_version: CONTRACT_SCHEMA.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            plugin_id: PLUGIN_ID.to_owned(),
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            api_revision: PROVIDER_API_REVISION.to_owned(),
            provider_version: provider.provider_version.clone(),
            contract_digest,
            api_digest,
            provider_digest: provider.provider_digest(),
            permission_digest: scope.permission_digest().clone(),
            scope_digest: scope.scope_digest(),
            evidence_digest,
            secret_reference_digest: secret.reference_digest().clone(),
            revision: Revision::new(1).map_err(GcpMonitoringAlertServiceError::Model)?,
            registration_digest,
            state: RegistrationState::Active,
        })
    }

    pub fn status(&self) -> RegistrationStatus {
        self.state.into()
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.state, RegistrationState::Active)
    }

    pub fn validate(&self) -> std::result::Result<(), GcpMonitoringAlertServiceError> {
        if self.schema_version != CONTRACT_SCHEMA
            || self.contract_version != CONTRACT_VERSION
            || self.plugin_id != PLUGIN_ID
            || self.service_id != SERVICE_ID
            || self.provider_id != PROVIDER_ID
            || self.consumer_id != CONSUMER_ID
            || self.plugin_version != PLUGIN_VERSION
            || self.api_revision != PROVIDER_API_REVISION
            || self.registration_digest
                != registration_digest(
                    &self.contract_digest,
                    &self.api_digest,
                    &self.provider_digest,
                    &self.permission_digest,
                    &self.scope_digest,
                    &self.evidence_digest,
                    &self.secret_reference_digest,
                    self.revision,
                )
        {
            return Err(GcpMonitoringAlertServiceError::TamperedEvidence);
        }
        Ok(())
    }

    pub fn reverse(
        &mut self,
    ) -> std::result::Result<RegistrationTransitionEvidence, GcpMonitoringAlertServiceError> {
        self.validate()?;
        if self.state == RegistrationState::Reversed {
            return Err(GcpMonitoringAlertServiceError::RegistrationTransition);
        }
        let from = self.status();
        self.state = RegistrationState::Reversed;
        let transition_digest = Digest::from_parts(
            "gcp-monitoring-registration-reverse/v1",
            &[
                ("registration", self.registration_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("revision", self.revision.get().to_string()),
            ],
        );
        Ok(RegistrationTransitionEvidence {
            from,
            to: self.status(),
            registration_digest: self.registration_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            revision: self.revision,
            transition_digest,
        })
    }

    pub fn restore(
        &mut self,
    ) -> std::result::Result<RegistrationTransitionEvidence, GcpMonitoringAlertServiceError> {
        self.validate()?;
        if self.state == RegistrationState::Active {
            return Err(GcpMonitoringAlertServiceError::RegistrationTransition);
        }
        let from = self.status();
        let next = self
            .revision
            .get()
            .checked_add(1)
            .ok_or(GcpMonitoringAlertServiceError::RegistrationTransition)?;
        self.revision = Revision::new(next).map_err(GcpMonitoringAlertServiceError::Model)?;
        self.registration_digest = registration_digest(
            &self.contract_digest,
            &self.api_digest,
            &self.provider_digest,
            &self.permission_digest,
            &self.scope_digest,
            &self.evidence_digest,
            &self.secret_reference_digest,
            self.revision,
        );
        self.state = RegistrationState::Active;
        let transition_digest = Digest::from_parts(
            "gcp-monitoring-registration-restore/v1",
            &[
                ("registration", self.registration_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("revision", self.revision.get().to_string()),
            ],
        );
        Ok(RegistrationTransitionEvidence {
            from,
            to: self.status(),
            registration_digest: self.registration_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            revision: self.revision,
            transition_digest,
        })
    }
}

fn registration_digest(
    contract_digest: &Digest,
    api_digest: &Digest,
    provider_digest: &Digest,
    permission_digest: &Digest,
    scope_digest: &Digest,
    evidence_digest: &Digest,
    secret_reference_digest: &Digest,
    revision: Revision,
) -> Digest {
    Digest::from_parts(
        "gcp-monitoring-registration/v1",
        &[
            ("contract", contract_digest.as_str().to_owned()),
            ("api", api_digest.as_str().to_owned()),
            ("provider", provider_digest.as_str().to_owned()),
            ("permission", permission_digest.as_str().to_owned()),
            ("scope", scope_digest.as_str().to_owned()),
            ("evidence", evidence_digest.as_str().to_owned()),
            ("secret", secret_reference_digest.as_str().to_owned()),
            ("revision", revision.get().to_string()),
        ],
    )
}

fn evidence_shape_digest() -> Digest {
    Digest::from_parts(
        "gcp-monitoring-evidence-shape/v1",
        &[
            (
                "operations",
                "alertPolicies.list,alertPolicies.get,alerts.list,alerts.get".to_owned(),
            ),
            (
                "required",
                "page-token,state,severity,redaction,proposal,record,read-back".to_owned(),
            ),
            ("raw-labels", "false".to_owned()),
            ("causal-incident-claim", "false".to_owned()),
        ],
    )
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpMonitoringAlertServiceDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub plugin_id: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub plugin_version: String,
    pub api_revision: String,
    pub evidence_level: String,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub external_writes: bool,
    pub dashboard_ui: bool,
    pub causal_incident_claim: bool,
}

impl Default for GcpMonitoringAlertServiceDefinition {
    fn default() -> Self {
        Self {
            schema_version: CONTRACT_SCHEMA.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            plugin_id: PLUGIN_ID.to_owned(),
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            api_revision: PROVIDER_API_REVISION.to_owned(),
            evidence_level: EVIDENCE_LEVEL.to_owned(),
            read_only: true,
            proposal_only: true,
            recording_only: true,
            external_writes: false,
            dashboard_ui: false,
            causal_incident_claim: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProposalRequest {
    pub limits: BoundedReadLimits,
    pub read_policy_gets: bool,
    pub read_alert_gets: bool,
}

impl ProposalRequest {
    pub fn new(limits: BoundedReadLimits) -> Self {
        Self {
            limits,
            read_policy_gets: true,
            read_alert_gets: true,
        }
    }

    pub fn list_only(limits: BoundedReadLimits) -> Self {
        Self {
            limits,
            read_policy_gets: false,
            read_alert_gets: false,
        }
    }
}

impl Default for ProposalRequest {
    fn default() -> Self {
        Self::new(BoundedReadLimits::default())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialReason {
    PolicyPageCap,
    AlertPageCap,
    PolicyCountCap,
    AlertCountCap,
    MissingPageToken,
    UnknownState,
    ProviderWarning,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultProjection {
    Complete,
    Partial(PartialReason),
    AccessLost,
    ProviderUnknown,
    FinalError,
    RegistrationReversed,
}

impl ResultProjection {
    pub const fn review_only(self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetryEvidence {
    pub operation: String,
    pub attempt: u8,
    pub kind: String,
    pub status_code: Option<u16>,
    pub error_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertEvidenceProjection {
    pub fence: EvidenceFence,
    pub scope: ScopeSummary,
    pub permissions: PermissionEvidence,
    pub policies_listed: Vec<AlertPolicyProjection>,
    pub policies_read_back: Vec<AlertPolicyProjection>,
    pub alerts_listed: Vec<AlertProjection>,
    pub alerts_read_back: Vec<AlertProjection>,
    pub policy_pages_observed: u16,
    pub alert_pages_observed: u16,
    pub page_token_digests: Vec<Digest>,
    pub list_response_digests: Vec<Digest>,
    pub get_response_digests: Vec<Digest>,
    pub provider_errors: Vec<crate::model::ProviderErrorEvidence>,
    pub retries: Vec<RetryEvidence>,
    pub redaction_complete: bool,
    pub raw_telemetry_retained: bool,
    pub raw_log_labels_retained: bool,
    pub dashboard_ui: bool,
    pub causal_incident_claim: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub durable_provider_receipt: bool,
    pub outcome_adopted: bool,
    pub evidence_digest: Digest,
    pub provider_provenance: ProviderProvenance,
}

pub type GcpMonitoringAlertEvidence = AlertEvidenceProjection;

impl AlertEvidenceProjection {
    fn new(
        fence: EvidenceFence,
        scope: ScopeSummary,
        permissions: PermissionEvidence,
        provider_provenance: ProviderProvenance,
    ) -> Self {
        let evidence_digest = Digest::from_parts(
            "gcp-monitoring-alert-evidence/v1",
            &[
                ("fence", fence.scope_digest.as_str().to_owned()),
                (
                    "permission",
                    permissions.permission_digest.as_str().to_owned(),
                ),
                ("scope", scope.metrics_scope_digest.as_str().to_owned()),
                ("provenance", format!("{provider_provenance:?}")),
            ],
        );
        Self {
            fence,
            scope,
            permissions,
            policies_listed: Vec::new(),
            policies_read_back: Vec::new(),
            alerts_listed: Vec::new(),
            alerts_read_back: Vec::new(),
            policy_pages_observed: 0,
            alert_pages_observed: 0,
            page_token_digests: Vec::new(),
            list_response_digests: Vec::new(),
            get_response_digests: Vec::new(),
            provider_errors: Vec::new(),
            retries: Vec::new(),
            redaction_complete: true,
            raw_telemetry_retained: false,
            raw_log_labels_retained: false,
            dashboard_ui: false,
            causal_incident_claim: false,
            connected: false,
            native: false,
            first_party: false,
            durable_provider_receipt: false,
            outcome_adopted: false,
            evidence_digest,
            provider_provenance,
        }
    }

    fn finalize_digest(&mut self) {
        self.evidence_digest = Digest::from_parts(
            "gcp-monitoring-alert-evidence/v1",
            &[
                ("fence", self.fence.scope_digest.as_str().to_owned()),
                (
                    "policies-list",
                    self.policies_listed
                        .iter()
                        .map(|policy| policy.policy_digest.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "policies-get",
                    self.policies_read_back
                        .iter()
                        .map(|policy| policy.policy_digest.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "alerts-list",
                    self.alerts_listed
                        .iter()
                        .map(|alert| alert.alert_digest.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "alerts-get",
                    self.alerts_read_back
                        .iter()
                        .map(|alert| alert.alert_digest.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "tokens",
                    self.page_token_digests
                        .iter()
                        .map(Digest::as_str)
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "responses",
                    self.list_response_digests
                        .iter()
                        .chain(&self.get_response_digests)
                        .map(Digest::as_str)
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "pages",
                    format!(
                        "{}:{}",
                        self.policy_pages_observed, self.alert_pages_observed
                    ),
                ),
                (
                    "provider-errors",
                    self.provider_errors
                        .iter()
                        .map(|error| {
                            format!(
                                "{}:{}:{}:{}:{}",
                                error.kind,
                                error.status_code.unwrap_or_default(),
                                error.retryable,
                                error.attempt,
                                error.diagnostic_digest.as_str()
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "retries",
                    self.retries
                        .iter()
                        .map(|retry| {
                            format!(
                                "{}:{}:{}:{}:{}",
                                retry.operation,
                                retry.attempt,
                                retry.kind,
                                retry.status_code.unwrap_or_default(),
                                retry.error_digest.as_str()
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                ("provenance", format!("{:?}", self.provider_provenance)),
            ],
        );
    }

    pub fn validate_integrity(&self) -> std::result::Result<(), GcpMonitoringAlertServiceError> {
        if !self.redaction_complete
            || self.raw_telemetry_retained
            || self.raw_log_labels_retained
            || self.dashboard_ui
            || self.causal_incident_claim
            || self.connected
            || self.native
            || self.first_party
            || self.durable_provider_receipt
            || self.outcome_adopted
        {
            return Err(GcpMonitoringAlertServiceError::TamperedEvidence);
        }
        for policy in self.policies_listed.iter().chain(&self.policies_read_back) {
            policy
                .validate()
                .map_err(|_| GcpMonitoringAlertServiceError::TamperedEvidence)?;
        }
        for alert in self.alerts_listed.iter().chain(&self.alerts_read_back) {
            alert
                .validate()
                .map_err(|_| GcpMonitoringAlertServiceError::TamperedEvidence)?;
        }
        let mut expected = self.clone();
        expected.finalize_digest();
        if expected.evidence_digest != self.evidence_digest {
            Err(GcpMonitoringAlertServiceError::TamperedEvidence)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpMonitoringAlertProposal {
    pub service_id: String,
    pub consumer_id: String,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub provider_definition_digest: Digest,
    pub scope_digest: Digest,
    pub mission_id: String,
    pub mission_revision: Revision,
    pub project_scope_id: String,
    pub project_revision: Revision,
    pub projection: ResultProjection,
    pub evidence: AlertEvidenceProjection,
    pub proposal_digest: Digest,
}

impl GcpMonitoringAlertProposal {
    pub fn is_review_only(&self) -> bool {
        true
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub fn validate_integrity(&self) -> std::result::Result<(), GcpMonitoringAlertServiceError> {
        if self.service_id != SERVICE_ID
            || self.consumer_id != CONSUMER_ID
            || self.scope_digest != self.evidence.fence.scope_digest
            || self.evidence.connected
            || self.evidence.native
            || self.evidence.first_party
            || self.evidence.durable_provider_receipt
            || self.evidence.outcome_adopted
            || self.evidence.causal_incident_claim
            || self.evidence.raw_telemetry_retained
            || self.evidence.raw_log_labels_retained
            || !self.evidence.redaction_complete
        {
            return Err(GcpMonitoringAlertServiceError::TamperedEvidence);
        }
        self.evidence.validate_integrity()?;
        let expected = proposal_digest(
            &self.registration_digest,
            self.registration_revision,
            &self.provider_definition_digest,
            &self.scope_digest,
            self.projection,
            &self.evidence.evidence_digest,
        );
        if expected != self.proposal_digest {
            Err(GcpMonitoringAlertServiceError::TamperedEvidence)
        } else {
            Ok(())
        }
    }
}

fn proposal_digest(
    registration_digest: &Digest,
    registration_revision: Revision,
    provider_definition_digest: &Digest,
    scope_digest: &Digest,
    projection: ResultProjection,
    evidence_digest: &Digest,
) -> Digest {
    Digest::from_parts(
        "gcp-monitoring-alert-proposal/v1",
        &[
            ("registration", registration_digest.as_str().to_owned()),
            ("revision", registration_revision.get().to_string()),
            ("provider", provider_definition_digest.as_str().to_owned()),
            ("scope", scope_digest.as_str().to_owned()),
            ("projection", format!("{projection:?}")),
            ("evidence", evidence_digest.as_str().to_owned()),
        ],
    )
}

pub struct GcpMonitoringAlertService<P: MonitoringProvider> {
    scope: GcpMonitoringAlertScope,
    secret_reference: SecretReference,
    provider: P,
    registration: GcpMonitoringAlertRegistration,
    definition: GcpMonitoringAlertServiceDefinition,
    retry_attempts: u8,
}

impl<P: MonitoringProvider> fmt::Debug for GcpMonitoringAlertService<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GcpMonitoringAlertService")
            .field("scope_digest", &self.scope.scope_digest())
            .field("registration", &self.registration)
            .field("provider", &self.provider.definition())
            .field("retry_attempts", &self.retry_attempts)
            .finish()
    }
}

impl<P: MonitoringProvider> GcpMonitoringAlertService<P> {
    pub fn new(
        scope: GcpMonitoringAlertScope,
        secret_reference: SecretReference,
        provider: P,
    ) -> std::result::Result<Self, GcpMonitoringAlertServiceError> {
        let default = BoundedReadLimits::default();
        let limits = BoundedReadLimits::new(
            default.max_pages.min(crate::MAX_PAGES),
            default
                .page_size
                .min(scope.policy.max_policies)
                .min(scope.alert.max_alerts),
            default
                .max_policies
                .min(usize::from(scope.policy.max_policies)),
            default.max_alerts.min(usize::from(scope.alert.max_alerts)),
            default.max_response_bytes,
        )?;
        Self::with_limits(scope, secret_reference, provider, limits)
    }

    pub fn with_limits(
        scope: GcpMonitoringAlertScope,
        secret_reference: SecretReference,
        provider: P,
        limits: BoundedReadLimits,
    ) -> std::result::Result<Self, GcpMonitoringAlertServiceError> {
        if secret_reference.scope_digest() != &scope.scope_digest() {
            return Err(GcpMonitoringAlertServiceError::ScopeMismatch);
        }
        if limits.max_policies > usize::from(scope.policy.max_policies)
            || limits.max_alerts > usize::from(scope.alert.max_alerts)
        {
            return Err(GcpMonitoringAlertServiceError::Model(
                GcpMonitoringAlertError::InvalidBound,
            ));
        }
        let registration =
            GcpMonitoringAlertRegistration::new(&scope, &secret_reference, provider.definition())?;
        Ok(Self {
            scope,
            secret_reference,
            provider,
            registration,
            definition: GcpMonitoringAlertServiceDefinition::default(),
            retry_attempts: MAX_RETRY_ATTEMPTS,
        })
    }

    pub fn definition(&self) -> &GcpMonitoringAlertServiceDefinition {
        &self.definition
    }

    pub fn describe_capabilities(&self) -> &GcpMonitoringAlertServiceDefinition {
        self.definition()
    }

    pub fn provider_definition(&self) -> &GcpMonitoringProviderDefinition {
        self.provider.definition()
    }

    pub fn registration(&self) -> &GcpMonitoringAlertRegistration {
        &self.registration
    }

    pub fn register(&self) -> &GcpMonitoringAlertRegistration {
        self.registration()
    }

    pub fn scope(&self) -> &GcpMonitoringAlertScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn provider(&self) -> &P {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut P {
        &mut self.provider
    }

    pub fn set_retry_attempts(
        &mut self,
        attempts: u8,
    ) -> std::result::Result<(), GcpMonitoringAlertServiceError> {
        if !(1..=MAX_RETRY_ATTEMPTS).contains(&attempts) {
            return Err(GcpMonitoringAlertServiceError::Model(
                GcpMonitoringAlertError::InvalidBound,
            ));
        }
        self.retry_attempts = attempts;
        Ok(())
    }

    pub fn reverse_registration(
        &mut self,
    ) -> std::result::Result<RegistrationTransitionEvidence, GcpMonitoringAlertServiceError> {
        self.registration.reverse()
    }

    pub fn revoke_registration(
        &mut self,
    ) -> std::result::Result<RegistrationTransitionEvidence, GcpMonitoringAlertServiceError> {
        self.reverse_registration()
    }

    pub fn restore_registration(
        &mut self,
    ) -> std::result::Result<RegistrationTransitionEvidence, GcpMonitoringAlertServiceError> {
        self.registration.restore()
    }

    pub fn revoke_secret(&mut self) -> Result<()> {
        self.secret_reference.revoke()
    }

    pub fn default_request(&self) -> ProposalRequest {
        ProposalRequest::default()
    }

    pub fn verify(
        &self,
        proposal: &GcpMonitoringAlertProposal,
    ) -> std::result::Result<(), GcpMonitoringAlertServiceError> {
        self.registration.validate()?;
        if !self.registration.is_active() {
            return Err(GcpMonitoringAlertServiceError::RegistrationReversed);
        }
        proposal.validate_integrity()?;
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.registration_revision != self.registration.revision
            || proposal.scope_digest != self.scope.scope_digest()
        {
            return Err(GcpMonitoringAlertServiceError::FenceMismatch);
        }
        Ok(())
    }

    pub fn propose(
        &mut self,
        request: ProposalRequest,
    ) -> std::result::Result<GcpMonitoringAlertProposal, GcpMonitoringAlertServiceError> {
        self.registration.validate()?;
        if !self.registration.is_active() {
            return Err(GcpMonitoringAlertServiceError::RegistrationReversed);
        }
        if self.secret_reference.is_revoked() {
            return Err(GcpMonitoringAlertServiceError::SecretRevoked);
        }
        let fence = self
            .scope
            .fence(self.secret_reference.credential_revision());
        let default_permissions = PermissionEvidence::default();
        let permissions = PermissionEvidence {
            permissions: default_permissions.permissions,
            permission_digest: self.scope.permission_digest().clone(),
        };
        let mut evidence = AlertEvidenceProjection::new(
            fence,
            ScopeSummary::from_scope(&self.scope),
            permissions,
            self.provider.provenance(),
        );
        let mut projection = ResultProjection::Complete;
        let mut seen_policy_pages = BTreeSet::new();
        let mut policy_token = None;
        let mut policy_page = 0_u16;

        loop {
            policy_page = policy_page.saturating_add(1);
            if policy_page > request.limits.max_pages {
                projection = ResultProjection::Partial(PartialReason::PolicyPageCap);
                break;
            }
            let list_request = ListAlertPoliciesRequest::for_scope(
                &self.scope,
                &self.secret_reference,
                request.limits.page_size,
                policy_token.take(),
            )?;
            let response = match self.list_policies_with_retry(&list_request, &mut evidence) {
                Ok(response) => response,
                Err(error) => {
                    projection = projection_for_error(error.kind);
                    break;
                }
            };
            validate_policy_list_response(&list_request, &response, &self.scope)?;
            if response.provider_provenance != evidence.provider_provenance {
                return Err(GcpMonitoringAlertServiceError::FenceMismatch);
            }
            evidence.policy_pages_observed = policy_page;
            evidence
                .list_response_digests
                .push(response.response_digest.clone());
            if let Some(token) = response.next_page_token.as_ref() {
                let token_digest = token.digest();
                if !seen_policy_pages.insert(token_digest.clone()) {
                    return Err(GcpMonitoringAlertServiceError::PaginationLoop);
                }
                evidence.page_token_digests.push(token_digest);
                policy_token = Some(token.clone());
            }
            for policy in response.policies {
                if evidence.policies_listed.len() >= request.limits.max_policies {
                    projection = ResultProjection::Partial(PartialReason::PolicyCountCap);
                    break;
                }
                if !self.scope.policy.contains(&policy.policy_id)
                    || evidence
                        .policies_listed
                        .iter()
                        .any(|existing| existing.policy_id == policy.policy_id)
                {
                    return Err(GcpMonitoringAlertServiceError::OutOfScope);
                }
                evidence.policies_listed.push(policy);
            }
            if policy_token.is_none() && response.total_size > evidence.policies_listed.len() as u64
            {
                projection = ResultProjection::Partial(PartialReason::MissingPageToken);
            }
            if !matches!(projection, ResultProjection::Complete) {
                break;
            }
            if policy_token.is_none() {
                break;
            }
        }

        if matches!(projection, ResultProjection::Complete) && request.read_policy_gets {
            for policy in evidence.policies_listed.clone() {
                let get_request = GetAlertPolicyRequest::for_scope(
                    &self.scope,
                    &self.secret_reference,
                    policy.policy_id.clone(),
                )?;
                let response = match self.get_policy_with_retry(&get_request, &mut evidence) {
                    Ok(response) => response,
                    Err(error) => {
                        projection = projection_for_error(error.kind);
                        break;
                    }
                };
                validate_policy_get_response(&get_request, &response, &self.scope)?;
                if response.provider_provenance != evidence.provider_provenance {
                    return Err(GcpMonitoringAlertServiceError::FenceMismatch);
                }
                evidence
                    .get_response_digests
                    .push(response.response_digest.clone());
                if response.policy.policy_digest != policy.policy_digest {
                    return Err(GcpMonitoringAlertServiceError::TamperedEvidence);
                }
                evidence.policies_read_back.push(response.policy);
            }
        }

        if matches!(projection, ResultProjection::Complete) {
            let mut seen_alert_pages = BTreeSet::new();
            let mut alert_token = None;
            let mut alert_page = 0_u16;
            loop {
                alert_page = alert_page.saturating_add(1);
                if alert_page > request.limits.max_pages {
                    projection = ResultProjection::Partial(PartialReason::AlertPageCap);
                    break;
                }
                let list_request = ListAlertsRequest::for_scope(
                    &self.scope,
                    &self.secret_reference,
                    request.limits.page_size,
                    alert_token.take(),
                )?;
                let response = match self.list_alerts_with_retry(&list_request, &mut evidence) {
                    Ok(response) => response,
                    Err(error) => {
                        projection = projection_for_error(error.kind);
                        break;
                    }
                };
                validate_alert_list_response(&list_request, &response, &self.scope)?;
                if response.provider_provenance != evidence.provider_provenance {
                    return Err(GcpMonitoringAlertServiceError::FenceMismatch);
                }
                evidence.alert_pages_observed = alert_page;
                evidence
                    .list_response_digests
                    .push(response.response_digest.clone());
                if let Some(token) = response.next_page_token.as_ref() {
                    let token_digest = token.digest();
                    if !seen_alert_pages.insert(token_digest.clone()) {
                        return Err(GcpMonitoringAlertServiceError::PaginationLoop);
                    }
                    evidence.page_token_digests.push(token_digest);
                    alert_token = Some(token.clone());
                }
                for alert in response.alerts {
                    if evidence.alerts_listed.len() >= request.limits.max_alerts {
                        projection = ResultProjection::Partial(PartialReason::AlertCountCap);
                        break;
                    }
                    validate_alert_projection(&alert, &self.scope, &evidence.policies_listed)?;
                    if alert.state == AlertState::Unspecified
                        || evidence
                            .policies_listed
                            .iter()
                            .find(|policy| policy.policy_id == alert.policy_id)
                            .is_some_and(|policy| policy.state == crate::PolicyState::Unknown)
                    {
                        projection = ResultProjection::Partial(PartialReason::UnknownState);
                    }
                    if evidence
                        .alerts_listed
                        .iter()
                        .any(|existing| existing.alert_id == alert.alert_id)
                    {
                        return Err(GcpMonitoringAlertServiceError::OutOfScope);
                    }
                    evidence.alerts_listed.push(alert);
                }
                if alert_token.is_none()
                    && response.total_size > evidence.alerts_listed.len() as u64
                {
                    projection = ResultProjection::Partial(PartialReason::MissingPageToken);
                }
                if !matches!(
                    projection,
                    ResultProjection::Complete
                        | ResultProjection::Partial(PartialReason::UnknownState)
                ) {
                    break;
                }
                if alert_token.is_none() {
                    break;
                }
            }
        }

        if matches!(
            projection,
            ResultProjection::Complete | ResultProjection::Partial(PartialReason::UnknownState)
        ) && request.read_alert_gets
        {
            for alert in evidence.alerts_listed.clone() {
                let get_request = GetAlertRequest::for_scope(
                    &self.scope,
                    &self.secret_reference,
                    alert.alert_id.clone(),
                )?;
                let response = match self.get_alert_with_retry(&get_request, &mut evidence) {
                    Ok(response) => response,
                    Err(error) => {
                        projection = projection_for_error(error.kind);
                        break;
                    }
                };
                validate_alert_get_response(
                    &get_request,
                    &response,
                    &self.scope,
                    &evidence.policies_listed,
                )?;
                if response.provider_provenance != evidence.provider_provenance {
                    return Err(GcpMonitoringAlertServiceError::FenceMismatch);
                }
                evidence
                    .get_response_digests
                    .push(response.response_digest.clone());
                if response.alert.alert_digest != alert.alert_digest {
                    return Err(GcpMonitoringAlertServiceError::TamperedEvidence);
                }
                evidence.alerts_read_back.push(response.alert);
            }
        }

        evidence.finalize_digest();
        let provider_definition_digest = self.provider.definition().provider_digest();
        let proposal_digest = proposal_digest(
            &self.registration.registration_digest,
            self.registration.revision,
            &provider_definition_digest,
            &self.scope.scope_digest(),
            projection,
            &evidence.evidence_digest,
        );
        Ok(GcpMonitoringAlertProposal {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            registration_digest: self.registration.registration_digest.clone(),
            registration_revision: self.registration.revision,
            provider_definition_digest,
            scope_digest: self.scope.scope_digest(),
            mission_id: self.scope.mission_id().as_str().to_owned(),
            mission_revision: self.scope.mission_revision(),
            project_scope_id: self.scope.project_scope_id().as_str().to_owned(),
            project_revision: self.scope.project_revision(),
            projection,
            evidence,
            proposal_digest,
        })
    }

    fn list_policies_with_retry(
        &mut self,
        request: &ListAlertPoliciesRequest,
        evidence: &mut AlertEvidenceProjection,
    ) -> std::result::Result<ListAlertPoliciesResponse, TransportError> {
        for attempt in 1..=self.retry_attempts {
            match self.provider.list_alert_policies(request) {
                Ok(response) => return Ok(response),
                Err(error) if error.retryable && attempt < self.retry_attempts => {
                    evidence
                        .retries
                        .push(retry_evidence("alertPolicies.list", attempt, &error));
                }
                Err(error) => {
                    evidence
                        .provider_errors
                        .push(provider_error_evidence(&error, attempt));
                    return Err(error);
                }
            }
        }
        unreachable!("bounded retry loop returns")
    }

    fn get_policy_with_retry(
        &mut self,
        request: &GetAlertPolicyRequest,
        evidence: &mut AlertEvidenceProjection,
    ) -> std::result::Result<GetAlertPolicyResponse, TransportError> {
        for attempt in 1..=self.retry_attempts {
            match self.provider.get_alert_policy(request) {
                Ok(response) => return Ok(response),
                Err(error) if error.retryable && attempt < self.retry_attempts => {
                    evidence
                        .retries
                        .push(retry_evidence("alertPolicies.get", attempt, &error));
                }
                Err(error) => {
                    evidence
                        .provider_errors
                        .push(provider_error_evidence(&error, attempt));
                    return Err(error);
                }
            }
        }
        unreachable!("bounded retry loop returns")
    }

    fn list_alerts_with_retry(
        &mut self,
        request: &ListAlertsRequest,
        evidence: &mut AlertEvidenceProjection,
    ) -> std::result::Result<ListAlertsResponse, TransportError> {
        for attempt in 1..=self.retry_attempts {
            match self.provider.list_alerts(request) {
                Ok(response) => return Ok(response),
                Err(error) if error.retryable && attempt < self.retry_attempts => {
                    evidence
                        .retries
                        .push(retry_evidence("alerts.list", attempt, &error));
                }
                Err(error) => {
                    evidence
                        .provider_errors
                        .push(provider_error_evidence(&error, attempt));
                    return Err(error);
                }
            }
        }
        unreachable!("bounded retry loop returns")
    }

    fn get_alert_with_retry(
        &mut self,
        request: &GetAlertRequest,
        evidence: &mut AlertEvidenceProjection,
    ) -> std::result::Result<GetAlertResponse, TransportError> {
        for attempt in 1..=self.retry_attempts {
            match self.provider.get_alert(request) {
                Ok(response) => return Ok(response),
                Err(error) if error.retryable && attempt < self.retry_attempts => {
                    evidence
                        .retries
                        .push(retry_evidence("alerts.get", attempt, &error));
                }
                Err(error) => {
                    evidence
                        .provider_errors
                        .push(provider_error_evidence(&error, attempt));
                    return Err(error);
                }
            }
        }
        unreachable!("bounded retry loop returns")
    }
}

fn retry_evidence(operation: &str, attempt: u8, error: &TransportError) -> RetryEvidence {
    RetryEvidence {
        operation: operation.to_owned(),
        attempt,
        kind: format!("{:?}", error.kind),
        status_code: error.status_code,
        error_digest: error.diagnostic_digest.clone(),
    }
}

fn provider_error_evidence(
    error: &TransportError,
    attempt: u8,
) -> crate::model::ProviderErrorEvidence {
    crate::model::ProviderErrorEvidence {
        kind: format!("{:?}", error.kind),
        status_code: error.status_code,
        retryable: error.retryable,
        attempt,
        diagnostic_digest: error.diagnostic_digest.clone(),
        blocked_env: error.blocked_env,
    }
}

fn projection_for_error(kind: TransportErrorKind) -> ResultProjection {
    match kind {
        TransportErrorKind::Unauthenticated | TransportErrorKind::PermissionDenied => {
            ResultProjection::AccessLost
        }
        TransportErrorKind::BadRequest | TransportErrorKind::Conflict => {
            ResultProjection::FinalError
        }
        TransportErrorKind::NotFound => ResultProjection::ProviderUnknown,
        TransportErrorKind::RateLimited
        | TransportErrorKind::ServerFailure
        | TransportErrorKind::Timeout
        | TransportErrorKind::BlockedEnv
        | TransportErrorKind::Unknown => ResultProjection::ProviderUnknown,
    }
}

fn validate_response_fence(
    observed_scope_digest: &Digest,
    observed_permission_digest: &Digest,
    observed_consent_digest: &Digest,
    observed_mission_revision: Revision,
    observed_project_revision: Revision,
    observed_credential_revision: Revision,
    request: &impl RequestFenceView,
) -> std::result::Result<(), GcpMonitoringAlertServiceError> {
    if observed_scope_digest != request.scope_digest()
        || observed_permission_digest != request.permission_digest()
        || observed_consent_digest != request.consent_digest()
        || observed_mission_revision != request.mission_revision()
        || observed_project_revision != request.project_revision()
        || observed_credential_revision != request.credential_revision()
    {
        Err(GcpMonitoringAlertServiceError::FenceMismatch)
    } else {
        Ok(())
    }
}

trait RequestFenceView {
    fn scope_digest(&self) -> &Digest;
    fn permission_digest(&self) -> &Digest;
    fn consent_digest(&self) -> &Digest;
    fn mission_revision(&self) -> Revision;
    fn project_revision(&self) -> Revision;
    fn credential_revision(&self) -> Revision;
}

macro_rules! impl_fence_view {
    ($type:ty) => {
        impl RequestFenceView for $type {
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

impl_fence_view!(ListAlertPoliciesRequest);
impl_fence_view!(GetAlertPolicyRequest);
impl_fence_view!(ListAlertsRequest);
impl_fence_view!(GetAlertRequest);

fn validate_policy_list_response(
    request: &ListAlertPoliciesRequest,
    response: &ListAlertPoliciesResponse,
    scope: &GcpMonitoringAlertScope,
) -> std::result::Result<(), GcpMonitoringAlertServiceError> {
    response
        .validate_digest()
        .map_err(|_| GcpMonitoringAlertServiceError::TamperedEvidence)?;
    if response.request_digest != request.request_digest {
        return Err(GcpMonitoringAlertServiceError::FenceMismatch);
    }
    validate_response_fence(
        &response.observed_scope_digest,
        &response.observed_permission_digest,
        &response.observed_consent_digest,
        response.observed_mission_revision,
        response.observed_project_revision,
        response.observed_credential_revision,
        request,
    )?;
    if response.policies.len() > usize::from(request.page_size)
        || response.provider_provenance.native()
        || response.provider_provenance.connected()
        || response.response_bytes > crate::MAX_RESPONSE_BYTES
        || response
            .policies
            .iter()
            .any(|policy| !scope.policy.contains(&policy.policy_id))
    {
        return Err(GcpMonitoringAlertServiceError::InvalidResponseShape);
    }
    Ok(())
}

fn validate_policy_get_response(
    request: &GetAlertPolicyRequest,
    response: &GetAlertPolicyResponse,
    scope: &GcpMonitoringAlertScope,
) -> std::result::Result<(), GcpMonitoringAlertServiceError> {
    response
        .validate_digest()
        .map_err(|_| GcpMonitoringAlertServiceError::TamperedEvidence)?;
    if response.request_digest != request.request_digest {
        return Err(GcpMonitoringAlertServiceError::FenceMismatch);
    }
    validate_response_fence(
        &response.observed_scope_digest,
        &response.observed_permission_digest,
        &response.observed_consent_digest,
        response.observed_mission_revision,
        response.observed_project_revision,
        response.observed_credential_revision,
        request,
    )?;
    if response.policy.policy_id != request.policy_id
        || !scope.policy.contains(&response.policy.policy_id)
        || response.provider_provenance.native()
        || response.provider_provenance.connected()
    {
        return Err(GcpMonitoringAlertServiceError::IdentityMismatch);
    }
    Ok(())
}

fn validate_alert_list_response(
    request: &ListAlertsRequest,
    response: &ListAlertsResponse,
    scope: &GcpMonitoringAlertScope,
) -> std::result::Result<(), GcpMonitoringAlertServiceError> {
    response
        .validate_digest()
        .map_err(|_| GcpMonitoringAlertServiceError::TamperedEvidence)?;
    if response.request_digest != request.request_digest {
        return Err(GcpMonitoringAlertServiceError::FenceMismatch);
    }
    validate_response_fence(
        &response.observed_scope_digest,
        &response.observed_permission_digest,
        &response.observed_consent_digest,
        response.observed_mission_revision,
        response.observed_project_revision,
        response.observed_credential_revision,
        request,
    )?;
    if response.alerts.len() > usize::from(request.page_size)
        || response.provider_provenance.native()
        || response.provider_provenance.connected()
        || response.response_bytes > crate::MAX_RESPONSE_BYTES
    {
        return Err(GcpMonitoringAlertServiceError::InvalidResponseShape);
    }
    for alert in &response.alerts {
        validate_alert_projection(alert, scope, &[])?;
    }
    Ok(())
}

fn validate_alert_projection(
    alert: &AlertProjection,
    scope: &GcpMonitoringAlertScope,
    policies: &[AlertPolicyProjection],
) -> std::result::Result<(), GcpMonitoringAlertServiceError> {
    alert
        .validate()
        .map_err(|_| GcpMonitoringAlertServiceError::TamperedEvidence)?;
    if !scope.alert.contains(&alert.alert_id)
        || !scope.alert.state_filter.matches(alert.state) && alert.state != AlertState::Unspecified
        || !scope.alert.severity_filter.matches(alert.severity)
        || !scope.policy.contains(&alert.policy_id)
        || alert
            .resource
            .as_ref()
            .is_some_and(|resource| !scope.resource.contains(resource))
        || (!policies.is_empty()
            && !policies
                .iter()
                .any(|policy| policy.policy_id == alert.policy_id))
    {
        return Err(GcpMonitoringAlertServiceError::OutOfScope);
    }
    Ok(())
}

fn validate_alert_get_response(
    request: &GetAlertRequest,
    response: &GetAlertResponse,
    scope: &GcpMonitoringAlertScope,
    policies: &[AlertPolicyProjection],
) -> std::result::Result<(), GcpMonitoringAlertServiceError> {
    response
        .validate_digest()
        .map_err(|_| GcpMonitoringAlertServiceError::TamperedEvidence)?;
    if response.request_digest != request.request_digest {
        return Err(GcpMonitoringAlertServiceError::FenceMismatch);
    }
    validate_response_fence(
        &response.observed_scope_digest,
        &response.observed_permission_digest,
        &response.observed_consent_digest,
        response.observed_mission_revision,
        response.observed_project_revision,
        response.observed_credential_revision,
        request,
    )?;
    if response.alert.alert_id != request.alert_id {
        return Err(GcpMonitoringAlertServiceError::IdentityMismatch);
    }
    validate_alert_projection(&response.alert, scope, policies)?;
    if let Some(policy) = policies
        .iter()
        .find(|policy| policy.policy_id == response.alert.policy_id)
        && policy.severity != response.alert.severity
    {
        return Err(GcpMonitoringAlertServiceError::PolicyAlertMismatch);
    }
    Ok(())
}
