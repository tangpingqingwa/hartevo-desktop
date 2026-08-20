//! Typed service, bounded proposal/read seams, verification, and reversible
//! registration for AWS Cost Anomaly Detection.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::consumer::MissionAwsCostAnomalyConsumer;
use crate::error::{AwsCostAnomalyError, AwsCostAnomalyTransportError, Result};
use crate::model::{
    AnomalyEvidenceState, AnomalyFilter, AnomalyMetadata, AnomalyProjection, AwsCostAnomalyScope,
    ConsentScope, Cursor, Digest, EvidenceDigests, MissionProjection, MonitorFilter,
    MonitorMetadata, MonitorProjection, PermissionSnapshot, ProjectProjection, SubscriptionFilter,
    SubscriptionMetadata, SubscriptionProjection, TransportProvenance, WorkProductProjection,
    mission_projection, project_projection, work_product_projection,
};
use crate::provider::{
    AwsCostAnomalyOperation, AwsCostAnomalyProvider, AwsCostAnomalyProviderDefinition,
    GetAnomaliesRequest, GetAnomaliesResponse, GetAnomalyMonitorsRequest,
    GetAnomalyMonitorsResponse, GetAnomalySubscriptionsRequest, GetAnomalySubscriptionsResponse,
};
use crate::{
    CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_VERSION, PLUGIN_VERSION, PROVIDER_ID, SERVICE_ID,
    contract_digest,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Active,
    Revoked,
    Reversed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationTransitionEvidence {
    pub previous_status: RegistrationStatus,
    pub new_status: RegistrationStatus,
    pub registration_digest: Digest,
    pub transition_digest: Digest,
}

impl RegistrationTransitionEvidence {
    fn new(
        previous_status: RegistrationStatus,
        new_status: RegistrationStatus,
        registration_digest: Digest,
    ) -> Self {
        let transition_digest = Digest::from_parts(
            "aws-cost-anomaly-registration-transition/v1",
            &[
                ("previous", format!("{previous_status:?}")),
                ("new", format!("{new_status:?}")),
                ("registration", registration_digest.as_str().to_owned()),
            ],
        );
        Self {
            previous_status,
            new_status,
            registration_digest,
            transition_digest,
        }
    }
}

/// Version/contract/provider/monitor/scope/permission/evidence/secret-bound
/// registration. The secret handle itself is never retained or serialized.
#[derive(Clone, Eq, PartialEq)]
pub struct AwsCostAnomalyRegistration {
    id: String,
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    provider_revision: u64,
    provider_release: String,
    provider_digest: Digest,
    monitor_digest: Digest,
    permission_snapshot: PermissionSnapshot,
    consent: ConsentScope,
    scope: AwsCostAnomalyScope,
    scope_digest: Digest,
    evidence_binding_digest: Digest,
    secret_reference: crate::model::SecretReference,
    registration_revision: u64,
    status: RegistrationStatus,
    binding_digest: Digest,
}

impl AwsCostAnomalyRegistration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        scope: AwsCostAnomalyScope,
        secret_reference: crate::model::SecretReference,
        permission_snapshot: PermissionSnapshot,
        consent: ConsentScope,
        provider: &AwsCostAnomalyProviderDefinition,
        registration_revision: u64,
    ) -> Result<Self> {
        let scope_digest = scope.digest();
        let evidence_binding_digest = Digest::from_parts(
            "aws-cost-anomaly-registration-evidence-binding/v1",
            &[
                ("scope", scope_digest.as_str().to_owned()),
                ("monitor", scope.monitor().digest().as_str().to_owned()),
                ("anomaly", scope.anomaly().digest().as_str().to_owned()),
                (
                    "subscription",
                    scope.subscription().digest().as_str().to_owned(),
                ),
            ],
        );
        let mut registration = Self {
            id: id.into(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: Digest::parse(CONTRACT_DIGEST.to_owned())?,
            provider_id: provider.provider_id.clone(),
            provider_revision: provider.provider_revision,
            provider_release: provider.release.clone(),
            provider_digest: provider.provider_digest.clone(),
            monitor_digest: scope.monitor().digest(),
            permission_snapshot,
            consent,
            scope,
            scope_digest,
            evidence_binding_digest,
            secret_reference,
            registration_revision,
            status: RegistrationStatus::Active,
            binding_digest: Digest::from_text("unsealed-aws-cost-anomaly-registration"),
        };
        registration.binding_digest = registration.calculate_binding_digest();
        registration.validate()?;
        Ok(registration)
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn plugin_version(&self) -> &str {
        &self.plugin_version
    }

    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }

    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub const fn provider_revision(&self) -> u64 {
        self.provider_revision
    }

    pub fn provider_release(&self) -> &str {
        &self.provider_release
    }

    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    pub fn monitor_digest(&self) -> &Digest {
        &self.monitor_digest
    }

    pub fn permission_snapshot(&self) -> &PermissionSnapshot {
        &self.permission_snapshot
    }

    pub fn permission_digest(&self) -> Digest {
        self.permission_snapshot.digest()
    }

    pub fn consent(&self) -> &ConsentScope {
        &self.consent
    }

    pub fn consent_digest(&self) -> Digest {
        self.consent.digest()
    }

    pub fn scope(&self) -> &AwsCostAnomalyScope {
        &self.scope
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn evidence_binding_digest(&self) -> &Digest {
        &self.evidence_binding_digest
    }

    pub fn secret_reference(&self) -> &crate::model::SecretReference {
        &self.secret_reference
    }

    pub fn secret_reference_digest(&self) -> &Digest {
        self.secret_reference.reference_digest()
    }

    pub const fn registration_revision(&self) -> u64 {
        self.registration_revision
    }

    pub const fn status(&self) -> RegistrationStatus {
        self.status
    }

    pub fn registration_digest(&self) -> &Digest {
        &self.binding_digest
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.status, RegistrationStatus::Active)
    }

    pub fn validate(&self) -> Result<()> {
        if !valid_id(&self.id)
            || self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest.as_str() != CONTRACT_DIGEST
            || self.contract_digest.as_str() != contract_digest()
            || self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.provider_release.is_empty()
            || self.monitor_digest != self.scope.monitor().digest()
            || self.registration_revision == 0
            || self.scope_digest != self.scope.digest()
            || self.evidence_binding_digest != self.calculate_evidence_binding_digest()
            || self.binding_digest != self.calculate_binding_digest()
        {
            return Err(AwsCostAnomalyError::InvalidRegistration);
        }
        self.permission_snapshot.validate()?;
        self.scope.validate()?;
        self.secret_reference.validate(&self.scope)?;
        if self
            .permission_snapshot
            .permissions
            .iter()
            .any(|permission| !self.consent.permissions().contains(permission))
        {
            return Err(AwsCostAnomalyError::InvalidConsent);
        }
        self.consent.validate()
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsCostAnomalyError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Revoked;
        self.binding_digest = self.calculate_binding_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.binding_digest.clone(),
        ))
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsCostAnomalyError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Reversed;
        self.binding_digest = self.calculate_binding_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.binding_digest.clone(),
        ))
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsCostAnomalyError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Active;
        self.binding_digest = self.calculate_binding_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.binding_digest.clone(),
        ))
    }

    fn calculate_evidence_binding_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-cost-anomaly-registration-evidence-binding/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("monitor", self.monitor_digest.as_str().to_owned()),
                ("anomaly", self.scope.anomaly().digest().as_str().to_owned()),
                (
                    "subscription",
                    self.scope.subscription().digest().as_str().to_owned(),
                ),
            ],
        )
    }

    fn calculate_binding_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-cost-anomaly-registration/v1",
            &[
                ("id", self.id.clone()),
                ("plugin_version", self.plugin_version.clone()),
                ("contract_version", self.contract_version.clone()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider_id", self.provider_id.clone()),
                ("provider_revision", self.provider_revision.to_string()),
                ("provider_release", self.provider_release.clone()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("monitor", self.monitor_digest.as_str().to_owned()),
                (
                    "permission",
                    self.permission_snapshot.digest().as_str().to_owned(),
                ),
                ("consent", self.consent.digest().as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("evidence", self.evidence_binding_digest.as_str().to_owned()),
                (
                    "secret",
                    self.secret_reference.reference_digest().as_str().to_owned(),
                ),
                ("revision", self.registration_revision.to_string()),
                ("status", format!("{:?}", self.status)),
            ],
        )
    }
}

impl fmt::Debug for AwsCostAnomalyRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsCostAnomalyRegistration")
            .field("id", &Digest::from_text(&self.id))
            .field("plugin_version", &self.plugin_version)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider_id", &self.provider_id)
            .field("provider_revision", &self.provider_revision)
            .field("provider_digest", &self.provider_digest)
            .field("monitor_digest", &self.monitor_digest)
            .field("permission_digest", &self.permission_digest())
            .field("consent_digest", &self.consent_digest())
            .field("scope_digest", &self.scope_digest)
            .field("evidence_binding_digest", &self.evidence_binding_digest)
            .field("secret_reference_digest", &self.secret_reference_digest())
            .field("registration_revision", &self.registration_revision)
            .field("status", &self.status)
            .field("registration_digest", &self.binding_digest)
            .finish()
    }
}

impl Serialize for AwsCostAnomalyRegistration {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AwsCostAnomalyRegistration", 17)?;
        state.serialize_field("idDigest", &Digest::from_text(&self.id))?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("providerRelease", &self.provider_release)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("monitorDigest", &self.monitor_digest)?;
        state.serialize_field("permissionDigest", &self.permission_digest())?;
        state.serialize_field("consentDigest", &self.consent_digest())?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("evidenceBindingDigest", &self.evidence_binding_digest)?;
        state.serialize_field("secretReferenceDigest", &self.secret_reference_digest())?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("registrationDigest", &self.binding_digest)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityDescription {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub operations: Vec<String>,
    pub permissions: Vec<String>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub outcome_adoption: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsCostAnomalyEvidenceRequest {
    pub scope_digest: Digest,
    pub anomaly_filter: AnomalyFilter,
    pub monitor_filter: MonitorFilter,
    pub subscription_filter: SubscriptionFilter,
    pub expected_provider_digest: Digest,
    pub expected_registration_digest: Digest,
    pub max_pages: u16,
    pub observed_at: DateTime<Utc>,
}

impl AwsCostAnomalyEvidenceRequest {
    pub fn new(
        scope: &AwsCostAnomalyScope,
        anomaly_filter: AnomalyFilter,
        monitor_filter: MonitorFilter,
        subscription_filter: SubscriptionFilter,
        expected_provider_digest: Digest,
        expected_registration_digest: Digest,
        max_pages: u16,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        anomaly_filter.validate_against(scope)?;
        monitor_filter.validate_against(scope)?;
        subscription_filter.validate_against(scope)?;
        if max_pages == 0 || max_pages > crate::MAX_PAGES {
            return Err(AwsCostAnomalyError::InvalidRequest);
        }
        expected_provider_digest.validate()?;
        expected_registration_digest.validate()?;
        scope
            .anomaly()
            .window()
            .validate_retention_at(observed_at)?;
        Ok(Self {
            scope_digest: scope.digest(),
            anomaly_filter,
            monitor_filter,
            subscription_filter,
            expected_provider_digest,
            expected_registration_digest,
            max_pages,
            observed_at,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-cost-anomaly-evidence-request/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "anomaly_filter",
                    self.anomaly_filter.digest().as_str().to_owned(),
                ),
                (
                    "monitor_filter",
                    self.monitor_filter.digest().as_str().to_owned(),
                ),
                (
                    "subscription_filter",
                    self.subscription_filter.digest().as_str().to_owned(),
                ),
                (
                    "provider",
                    self.expected_provider_digest.as_str().to_owned(),
                ),
                (
                    "registration",
                    self.expected_registration_digest.as_str().to_owned(),
                ),
                ("max_pages", self.max_pages.to_string()),
                ("observed_at", self.observed_at.to_rfc3339()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailureEvidence {
    pub operation: AwsCostAnomalyOperation,
    pub status_code: Option<u16>,
    pub category: String,
    pub failure_digest: Digest,
}

impl FailureEvidence {
    fn from_transport(
        operation: AwsCostAnomalyOperation,
        error: &AwsCostAnomalyTransportError,
    ) -> Self {
        let category = match error {
            AwsCostAnomalyTransportError::BlockedEnv => "blocked_env",
            AwsCostAnomalyTransportError::BadRequest => "bad_request",
            AwsCostAnomalyTransportError::Unauthorized => "unauthorized",
            AwsCostAnomalyTransportError::Forbidden => "forbidden",
            AwsCostAnomalyTransportError::NotFound => "not_found",
            AwsCostAnomalyTransportError::Conflict => "conflict",
            AwsCostAnomalyTransportError::RateLimited { .. } => "throttled",
            AwsCostAnomalyTransportError::ServerError { .. } => "server_error",
            AwsCostAnomalyTransportError::Timeout => "timeout",
            AwsCostAnomalyTransportError::AccessLost => "access_loss",
            AwsCostAnomalyTransportError::Partial => "partial",
            AwsCostAnomalyTransportError::InvalidResponse => "invalid_response",
        }
        .to_owned();
        let failure_digest = Digest::from_parts(
            "aws-cost-anomaly-failure/v1",
            &[
                ("operation", operation.as_str().to_owned()),
                ("category", category.clone()),
                (
                    "status",
                    error
                        .status_code()
                        .map_or_else(String::new, |status| status.to_string()),
                ),
            ],
        );
        Self {
            operation,
            status_code: error.status_code(),
            category,
            failure_digest,
        }
    }

    fn pagination_loop(operation: AwsCostAnomalyOperation) -> Self {
        let category = "pagination_loop".to_owned();
        Self {
            operation,
            status_code: None,
            failure_digest: Digest::from_parts(
                "aws-cost-anomaly-failure/v1",
                &[
                    ("operation", operation.as_str().to_owned()),
                    ("category", category.clone()),
                    ("status", String::new()),
                ],
            ),
            category,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsCostAnomalyProposal {
    pub service_id: String,
    pub consumer_id: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub evidence_binding_digest: Digest,
    pub management_account_digest: Digest,
    pub account_digest: Digest,
    pub region_digest: Digest,
    pub monitor_digest: Digest,
    pub anomaly_identity_digest: Digest,
    pub subscription_digest: Digest,
    pub deployment_digest: Digest,
    pub service_revision_digest: Digest,
    pub mission: MissionProjection,
    pub project: ProjectProjection,
    pub work_product: WorkProductProjection,
    pub state: AnomalyEvidenceState,
    pub anomaly_pages: u16,
    pub monitor_pages: u16,
    pub subscription_pages: u16,
    pub anomaly_complete: bool,
    pub monitor_complete: bool,
    pub subscription_complete: bool,
    pub anomaly: Option<AnomalyProjection>,
    pub monitor: Option<MonitorProjection>,
    pub subscription: Option<SubscriptionProjection>,
    pub failure: Option<FailureEvidence>,
    pub evidence: EvidenceDigests,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub financial_advice: bool,
    pub cost_causality_claim: bool,
    pub notification_sent: bool,
    pub billing_effect: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub proposal_digest: Digest,
}

impl AwsCostAnomalyProposal {
    #[allow(clippy::too_many_arguments)]
    fn new(
        registration: &AwsCostAnomalyRegistration,
        provider: &AwsCostAnomalyProviderDefinition,
        request: &AwsCostAnomalyEvidenceRequest,
        state: AnomalyEvidenceState,
        pages: (u16, u16, u16),
        completeness: (bool, bool, bool),
        evidence_page_digests: (Option<Digest>, Option<Digest>, Option<Digest>),
        cursor_digest: Option<Digest>,
        anomaly: Option<&AnomalyMetadata>,
        monitor: Option<&MonitorMetadata>,
        subscription: Option<&SubscriptionMetadata>,
        failure: Option<FailureEvidence>,
        provenance: TransportProvenance,
    ) -> Self {
        let evidence = EvidenceDigests {
            plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_digest: registration.contract_digest.clone(),
            provider_digest: provider.provider_digest.clone(),
            monitor_digest: registration.monitor_digest.clone(),
            permission_digest: registration.permission_digest(),
            consent_digest: registration.consent_digest(),
            scope_digest: registration.scope_digest.clone(),
            filter_digest: request.digest(),
            cursor_digest,
            anomalies_digest: evidence_page_digests.0,
            monitors_digest: evidence_page_digests.1,
            subscriptions_digest: evidence_page_digests.2,
            evidence_digest: Digest::from_text("unsealed-aws-cost-anomaly-evidence"),
        };
        let mut proposal = Self {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            registration_digest: registration.registration_digest().clone(),
            scope_digest: registration.scope_digest.clone(),
            evidence_binding_digest: registration.evidence_binding_digest().clone(),
            management_account_digest: registration.scope().management_account().digest(),
            account_digest: registration.scope().account().digest(),
            region_digest: registration.scope().region().digest(),
            monitor_digest: registration.scope().monitor().digest(),
            anomaly_identity_digest: registration.scope().anomaly().digest(),
            subscription_digest: registration.scope().subscription().digest(),
            deployment_digest: registration.scope().deployment().digest(),
            service_revision_digest: registration.scope().service_revision().digest(),
            mission: mission_projection(registration.scope().mission()),
            project: project_projection(registration.scope().project()),
            work_product: work_product_projection(registration.scope().work_product()),
            state,
            anomaly_pages: pages.0,
            monitor_pages: pages.1,
            subscription_pages: pages.2,
            anomaly_complete: completeness.0,
            monitor_complete: completeness.1,
            subscription_complete: completeness.2,
            anomaly: anomaly.map(AnomalyProjection::from),
            monitor: monitor.map(MonitorProjection::from),
            subscription: subscription.map(SubscriptionProjection::from),
            failure,
            evidence,
            provenance,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            financial_advice: false,
            cost_causality_claim: false,
            notification_sent: false,
            billing_effect: false,
            outcome_adopted: false,
            work_product_adopted: false,
            proposal_digest: Digest::from_text("unsealed-aws-cost-anomaly-proposal"),
        };
        proposal.evidence.evidence_digest = calculate_evidence_digest(&proposal);
        proposal.proposal_digest = proposal.calculate_proposal_digest();
        proposal
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub const fn is_review_only(&self) -> bool {
        true
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.financial_advice
            || self.cost_causality_claim
            || self.notification_sent
            || self.billing_effect
            || self.outcome_adopted
            || self.work_product_adopted
            || self.evidence.evidence_digest != calculate_evidence_digest(self)
            || self.proposal_digest != self.calculate_proposal_digest()
        {
            Err(AwsCostAnomalyError::TamperedEvidence)
        } else {
            Ok(())
        }
    }

    fn calculate_proposal_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-cost-anomaly-proposal/v1",
            &[
                ("service", self.service_id.clone()),
                ("consumer", self.consumer_id.clone()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("state", format!("{:?}", self.state)),
                ("anomaly_pages", self.anomaly_pages.to_string()),
                ("monitor_pages", self.monitor_pages.to_string()),
                ("subscription_pages", self.subscription_pages.to_string()),
                ("anomaly_complete", self.anomaly_complete.to_string()),
                ("monitor_complete", self.monitor_complete.to_string()),
                (
                    "subscription_complete",
                    self.subscription_complete.to_string(),
                ),
                (
                    "evidence",
                    self.evidence.evidence_digest.as_str().to_owned(),
                ),
                (
                    "anomaly",
                    self.anomaly.as_ref().map_or_else(String::new, |value| {
                        serde_json::to_string(value).expect("projection serializes")
                    }),
                ),
                (
                    "monitor",
                    self.monitor.as_ref().map_or_else(String::new, |value| {
                        serde_json::to_string(value).expect("projection serializes")
                    }),
                ),
                (
                    "subscription",
                    self.subscription
                        .as_ref()
                        .map_or_else(String::new, |value| {
                            serde_json::to_string(value).expect("projection serializes")
                        }),
                ),
                (
                    "failure",
                    self.failure.as_ref().map_or_else(String::new, |value| {
                        serde_json::to_string(value).expect("failure serializes")
                    }),
                ),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AwsCostAnomalyVerificationFailure {
    RegistrationInactive,
    RegistrationDigestMismatch,
    ContractDigestMismatch,
    ProviderDigestMismatch,
    MonitorDigestMismatch,
    PermissionDigestMismatch,
    ConsentDigestMismatch,
    ScopeDigestMismatch,
    EvidenceBindingMismatch,
    TamperedEvidence,
    PartialEvidence,
    RetentionExpired,
    AccessLoss,
    Throttled,
    ProviderUnknown,
    NotFound,
    InactiveMonitor,
    InactiveSubscription,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub valid: bool,
    pub review_eligible: bool,
    pub failures: Vec<AwsCostAnomalyVerificationFailure>,
    pub verification_digest: Digest,
}

impl VerificationReport {
    fn new(
        valid: bool,
        review_eligible: bool,
        mut failures: Vec<AwsCostAnomalyVerificationFailure>,
    ) -> Self {
        failures.sort_unstable();
        failures.dedup();
        let verification_digest = Digest::from_parts(
            "aws-cost-anomaly-verification/v1",
            &[
                ("valid", valid.to_string()),
                ("review_eligible", review_eligible.to_string()),
                (
                    "failures",
                    failures
                        .iter()
                        .map(|failure| format!("{failure:?}"))
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
            ],
        );
        Self {
            valid,
            review_eligible,
            failures,
            verification_digest,
        }
    }
}

pub struct AwsCostAnomalyService<T> {
    registration: AwsCostAnomalyRegistration,
    provider: AwsCostAnomalyProvider<T>,
}

impl<T: crate::provider::AwsCostAnomalyTransport> fmt::Debug for AwsCostAnomalyService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsCostAnomalyService")
            .field("registration", &self.registration)
            .field("provider", &self.provider)
            .finish()
    }
}

impl<T: crate::provider::AwsCostAnomalyTransport> AwsCostAnomalyService<T> {
    pub fn new(
        scope: AwsCostAnomalyScope,
        secret_reference: crate::model::SecretReference,
        consent: ConsentScope,
        provider: AwsCostAnomalyProvider<T>,
        registration_time: DateTime<Utc>,
    ) -> Result<Self> {
        Self::with_registration(
            "aws-cost-anomaly-registration",
            scope,
            secret_reference,
            PermissionSnapshot::for_layer_one(1),
            consent,
            provider,
            1,
            registration_time,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_registration(
        registration_id: impl Into<String>,
        scope: AwsCostAnomalyScope,
        secret_reference: crate::model::SecretReference,
        permission_snapshot: PermissionSnapshot,
        consent: ConsentScope,
        provider: AwsCostAnomalyProvider<T>,
        registration_revision: u64,
        _registration_time: DateTime<Utc>,
    ) -> Result<Self> {
        let registration = AwsCostAnomalyRegistration::new(
            registration_id,
            scope,
            secret_reference,
            permission_snapshot,
            consent,
            provider.definition(),
            registration_revision,
        )?;
        Ok(Self {
            registration,
            provider,
        })
    }

    pub fn describe_capabilities(&self) -> CapabilityDescription {
        CapabilityDescription {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            operations: vec![
                AwsCostAnomalyOperation::GetAnomalies.as_str().to_owned(),
                AwsCostAnomalyOperation::GetAnomalyMonitors
                    .as_str()
                    .to_owned(),
                AwsCostAnomalyOperation::GetAnomalySubscriptions
                    .as_str()
                    .to_owned(),
            ],
            permissions: crate::LAYER1_PERMISSIONS
                .iter()
                .map(|permission| (*permission).to_owned())
                .collect(),
            read_only: true,
            proposal_only: true,
            connected: false,
            native: false,
            first_party: false,
            outcome_adoption: false,
        }
    }

    pub fn scope(&self) -> &AwsCostAnomalyScope {
        self.registration.scope()
    }

    pub fn registration(&self) -> &AwsCostAnomalyRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut AwsCostAnomalyRegistration {
        &mut self.registration
    }

    pub fn provider(&self) -> &AwsCostAnomalyProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsCostAnomalyProvider<T> {
        &mut self.provider
    }

    pub fn request(
        &self,
        anomaly_filter: AnomalyFilter,
        monitor_filter: MonitorFilter,
        subscription_filter: SubscriptionFilter,
        max_pages: u16,
        observed_at: DateTime<Utc>,
    ) -> Result<AwsCostAnomalyEvidenceRequest> {
        AwsCostAnomalyEvidenceRequest::new(
            self.scope(),
            anomaly_filter,
            monitor_filter,
            subscription_filter,
            self.provider.definition().provider_digest.clone(),
            self.registration.registration_digest().clone(),
            max_pages,
            observed_at,
        )
    }

    pub fn default_request(
        &self,
        observed_at: DateTime<Utc>,
    ) -> Result<AwsCostAnomalyEvidenceRequest> {
        self.request(
            AnomalyFilter::for_scope(self.scope(), 10)?,
            MonitorFilter::for_scope(self.scope(), 10)?,
            SubscriptionFilter::for_scope(self.scope(), 10)?,
            1,
            observed_at,
        )
    }

    pub fn read_anomalies(
        &mut self,
        request: &GetAnomaliesRequest,
    ) -> Result<GetAnomaliesResponse> {
        self.provider
            .get_anomalies(request)
            .map_err(AwsCostAnomalyError::from)
    }

    pub fn read_anomaly_monitors(
        &mut self,
        request: &GetAnomalyMonitorsRequest,
    ) -> Result<GetAnomalyMonitorsResponse> {
        self.provider
            .get_anomaly_monitors(request)
            .map_err(AwsCostAnomalyError::from)
    }

    pub fn read_anomaly_subscriptions(
        &mut self,
        request: &GetAnomalySubscriptionsRequest,
    ) -> Result<GetAnomalySubscriptionsResponse> {
        self.provider
            .get_anomaly_subscriptions(request)
            .map_err(AwsCostAnomalyError::from)
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.revoke()
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.reverse()
    }

    pub fn restore_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.restore()
    }

    pub fn consumer(&self) -> Result<MissionAwsCostAnomalyConsumer> {
        MissionAwsCostAnomalyConsumer::new(self.scope().clone(), self.registration.clone())
    }

    pub fn verify(&self, proposal: &AwsCostAnomalyProposal) -> VerificationReport {
        let mut failures = Vec::new();
        if !self.registration.is_active() {
            failures.push(AwsCostAnomalyVerificationFailure::RegistrationInactive);
        }
        if proposal.registration_digest != *self.registration.registration_digest() {
            failures.push(AwsCostAnomalyVerificationFailure::RegistrationDigestMismatch);
        }
        if proposal.evidence.contract_digest != self.registration.contract_digest {
            failures.push(AwsCostAnomalyVerificationFailure::ContractDigestMismatch);
        }
        if proposal.evidence.provider_digest != self.provider.definition().provider_digest {
            failures.push(AwsCostAnomalyVerificationFailure::ProviderDigestMismatch);
        }
        if proposal.evidence.monitor_digest != *self.registration.monitor_digest() {
            failures.push(AwsCostAnomalyVerificationFailure::MonitorDigestMismatch);
        }
        if proposal.evidence.permission_digest != self.registration.permission_digest() {
            failures.push(AwsCostAnomalyVerificationFailure::PermissionDigestMismatch);
        }
        if proposal.evidence.consent_digest != self.registration.consent_digest() {
            failures.push(AwsCostAnomalyVerificationFailure::ConsentDigestMismatch);
        }
        if proposal.scope_digest != *self.registration.scope_digest() {
            failures.push(AwsCostAnomalyVerificationFailure::ScopeDigestMismatch);
        }
        if proposal.evidence_binding_digest != *self.registration.evidence_binding_digest() {
            failures.push(AwsCostAnomalyVerificationFailure::EvidenceBindingMismatch);
        }
        if proposal.validate_integrity().is_err() {
            failures.push(AwsCostAnomalyVerificationFailure::TamperedEvidence);
        }
        match proposal.state {
            AnomalyEvidenceState::Partial => {
                failures.push(AwsCostAnomalyVerificationFailure::PartialEvidence);
            }
            AnomalyEvidenceState::RetentionExpired => {
                failures.push(AwsCostAnomalyVerificationFailure::RetentionExpired);
            }
            AnomalyEvidenceState::AccessLoss => {
                failures.push(AwsCostAnomalyVerificationFailure::AccessLoss);
            }
            AnomalyEvidenceState::Throttled => {
                failures.push(AwsCostAnomalyVerificationFailure::Throttled);
            }
            AnomalyEvidenceState::ProviderUnknown => {
                failures.push(AwsCostAnomalyVerificationFailure::ProviderUnknown);
            }
            AnomalyEvidenceState::NotFound => {
                failures.push(AwsCostAnomalyVerificationFailure::NotFound);
            }
            AnomalyEvidenceState::MonitorInactive => {
                failures.push(AwsCostAnomalyVerificationFailure::InactiveMonitor);
            }
            AnomalyEvidenceState::SubscriptionInactive => {
                failures.push(AwsCostAnomalyVerificationFailure::InactiveSubscription);
            }
            AnomalyEvidenceState::RegistrationRevoked => {
                failures.push(AwsCostAnomalyVerificationFailure::RegistrationInactive);
            }
            AnomalyEvidenceState::AnomalyDetected
            | AnomalyEvidenceState::NoAnomaly
            | AnomalyEvidenceState::MonitorActive
            | AnomalyEvidenceState::SubscriptionActive => {}
        }
        failures.sort_unstable();
        failures.dedup();
        let valid = failures.is_empty();
        VerificationReport::new(
            valid,
            valid && proposal.state.is_review_complete(),
            failures,
        )
    }

    pub fn propose(
        &mut self,
        request: AwsCostAnomalyEvidenceRequest,
    ) -> Result<AwsCostAnomalyProposal> {
        self.registration.validate()?;
        if !self.registration.is_active() {
            return Err(AwsCostAnomalyError::RegistrationInactive);
        }
        if request.scope_digest != *self.registration.scope_digest()
            || request.expected_provider_digest != self.provider.definition().provider_digest
            || request.expected_registration_digest != *self.registration.registration_digest()
        {
            return Err(AwsCostAnomalyError::ScopeMismatch);
        }
        request.anomaly_filter.validate_against(self.scope())?;
        request.monitor_filter.validate_against(self.scope())?;
        request.subscription_filter.validate_against(self.scope())?;
        if self.registration.consent().is_revoked() {
            return Err(AwsCostAnomalyError::ConsentRevoked);
        }
        if !self
            .registration
            .consent()
            .is_active_at(request.observed_at)
        {
            return Err(AwsCostAnomalyError::ConsentExpired);
        }
        self.scope()
            .anomaly()
            .window()
            .validate_retention_at(request.observed_at)?;

        let (
            anomaly,
            anomaly_pages,
            anomaly_complete,
            anomaly_digest,
            anomaly_cursor,
            anomaly_failure,
        ) = self.read_anomaly_pages(&request)?;
        if let Some(failure) = anomaly_failure {
            return Ok(self.proposal_with(
                &request,
                state_from_failure(&failure),
                (anomaly_pages, 0, 0),
                (anomaly_complete, false, false),
                (anomaly_digest, None, None),
                anomaly_cursor,
                anomaly.as_ref(),
                None,
                None,
                Some(failure),
            ));
        }

        let (
            monitor,
            monitor_pages,
            monitor_complete,
            monitor_digest,
            monitor_cursor,
            monitor_failure,
        ) = self.read_monitor_pages(&request)?;
        if let Some(failure) = monitor_failure {
            return Ok(self.proposal_with(
                &request,
                state_from_failure(&failure),
                (anomaly_pages, monitor_pages, 0),
                (anomaly_complete, monitor_complete, false),
                (anomaly_digest, monitor_digest, None),
                monitor_cursor.or(anomaly_cursor),
                anomaly.as_ref(),
                monitor.as_ref(),
                None,
                Some(failure),
            ));
        }

        let (
            subscription,
            subscription_pages,
            subscription_complete,
            subscription_digest,
            subscription_cursor,
            subscription_failure,
        ) = self.read_subscription_pages(&request)?;
        if let Some(failure) = subscription_failure {
            return Ok(self.proposal_with(
                &request,
                state_from_failure(&failure),
                (anomaly_pages, monitor_pages, subscription_pages),
                (anomaly_complete, monitor_complete, subscription_complete),
                (anomaly_digest, monitor_digest, subscription_digest),
                subscription_cursor.or(monitor_cursor).or(anomaly_cursor),
                anomaly.as_ref(),
                monitor.as_ref(),
                subscription.as_ref(),
                Some(failure),
            ));
        }

        let state = if !anomaly_complete || !monitor_complete || !subscription_complete {
            AnomalyEvidenceState::Partial
        } else if anomaly.is_none() || monitor.is_none() || subscription.is_none() {
            AnomalyEvidenceState::NotFound
        } else if !matches!(
            monitor.as_ref().map(MonitorMetadata::status),
            Some(crate::model::MonitorStatus::Active)
        ) {
            AnomalyEvidenceState::MonitorInactive
        } else if !matches!(
            subscription.as_ref().map(SubscriptionMetadata::status),
            Some(crate::model::SubscriptionStatus::Active)
        ) {
            AnomalyEvidenceState::SubscriptionInactive
        } else {
            AnomalyEvidenceState::AnomalyDetected
        };
        Ok(self.proposal_with(
            &request,
            state,
            (anomaly_pages, monitor_pages, subscription_pages),
            (anomaly_complete, monitor_complete, subscription_complete),
            (anomaly_digest, monitor_digest, subscription_digest),
            subscription_cursor.or(monitor_cursor).or(anomaly_cursor),
            anomaly.as_ref(),
            monitor.as_ref(),
            subscription.as_ref(),
            None,
        ))
    }

    fn read_anomaly_pages(
        &mut self,
        request: &AwsCostAnomalyEvidenceRequest,
    ) -> Result<(
        Option<AnomalyMetadata>,
        u16,
        bool,
        Option<Digest>,
        Option<Digest>,
        Option<FailureEvidence>,
    )> {
        let mut cursor: Option<Cursor> = None;
        let mut seen = BTreeSet::new();
        let mut pages = 0_u16;
        let mut complete = false;
        let mut page_digests = Vec::new();
        let mut target = None;
        let mut final_cursor = None;
        while pages < request.max_pages {
            let page_request = GetAnomaliesRequest::new(
                self.scope(),
                request.anomaly_filter.clone(),
                cursor.clone(),
            )?;
            if let Some(cursor) = page_request.cursor() {
                if !seen.insert(cursor.token_digest().clone()) {
                    return Ok((
                        target,
                        pages,
                        false,
                        nonempty_digest(&page_digests),
                        final_cursor,
                        Some(FailureEvidence::pagination_loop(
                            AwsCostAnomalyOperation::GetAnomalies,
                        )),
                    ));
                }
            }
            let response = match self.read_anomalies(&page_request) {
                Ok(response) => response,
                Err(AwsCostAnomalyError::Transport(error)) => {
                    let failure = FailureEvidence::from_transport(
                        AwsCostAnomalyOperation::GetAnomalies,
                        &error,
                    );
                    return Ok((
                        target,
                        pages,
                        false,
                        nonempty_digest(&page_digests),
                        final_cursor,
                        Some(failure),
                    ));
                }
                Err(error) => return Err(error),
            };
            pages = pages.saturating_add(1);
            page_digests.push(response.evidence_digest.clone());
            for candidate in response.anomalies {
                if candidate.identity().id() == self.scope().anomaly().id() {
                    if let Some(previous) = &target {
                        if previous.digest() != candidate.digest() {
                            return Ok((
                                target,
                                pages,
                                false,
                                nonempty_digest(&page_digests),
                                final_cursor,
                                Some(FailureEvidence {
                                    operation: AwsCostAnomalyOperation::GetAnomalies,
                                    status_code: None,
                                    category: "target_replaced".to_owned(),
                                    failure_digest: Digest::from_text(
                                        "aws-cost-anomaly-target-replaced",
                                    ),
                                }),
                            ));
                        }
                    }
                    target = Some(candidate);
                }
            }
            if let Some(next) = response.next_cursor {
                final_cursor = Some(next.token_digest().clone());
                cursor = Some(next);
            } else {
                complete = true;
                break;
            }
        }
        if !complete {
            final_cursor = cursor.map(|cursor| cursor.token_digest().clone());
        }
        Ok((
            target,
            pages,
            complete,
            nonempty_digest(&page_digests),
            final_cursor,
            None,
        ))
    }

    fn read_monitor_pages(
        &mut self,
        request: &AwsCostAnomalyEvidenceRequest,
    ) -> Result<(
        Option<MonitorMetadata>,
        u16,
        bool,
        Option<Digest>,
        Option<Digest>,
        Option<FailureEvidence>,
    )> {
        let mut cursor = None;
        let mut seen = BTreeSet::new();
        let mut pages = 0_u16;
        let mut complete = false;
        let mut page_digests = Vec::new();
        let mut target = None;
        let mut final_cursor = None;
        while pages < request.max_pages {
            let page_request = GetAnomalyMonitorsRequest::new(
                self.scope(),
                request.monitor_filter.clone(),
                cursor.clone(),
            )?;
            if let Some(cursor) = page_request.cursor() {
                if !seen.insert(cursor.token_digest().clone()) {
                    return Ok((
                        target,
                        pages,
                        false,
                        nonempty_digest(&page_digests),
                        final_cursor,
                        Some(FailureEvidence::pagination_loop(
                            AwsCostAnomalyOperation::GetAnomalyMonitors,
                        )),
                    ));
                }
            }
            let response = match self.read_anomaly_monitors(&page_request) {
                Ok(response) => response,
                Err(AwsCostAnomalyError::Transport(error)) => {
                    let failure = FailureEvidence::from_transport(
                        AwsCostAnomalyOperation::GetAnomalyMonitors,
                        &error,
                    );
                    return Ok((
                        target,
                        pages,
                        false,
                        nonempty_digest(&page_digests),
                        final_cursor,
                        Some(failure),
                    ));
                }
                Err(error) => return Err(error),
            };
            pages = pages.saturating_add(1);
            page_digests.push(response.evidence_digest.clone());
            for candidate in response.monitors {
                if candidate.arn().digest() == *self.registration.monitor_digest() {
                    target = Some(candidate);
                }
            }
            if let Some(next) = response.next_cursor {
                final_cursor = Some(next.token_digest().clone());
                cursor = Some(next);
            } else {
                complete = true;
                break;
            }
        }
        if !complete {
            final_cursor = cursor.map(|cursor| cursor.token_digest().clone());
        }
        Ok((
            target,
            pages,
            complete,
            nonempty_digest(&page_digests),
            final_cursor,
            None,
        ))
    }

    fn read_subscription_pages(
        &mut self,
        request: &AwsCostAnomalyEvidenceRequest,
    ) -> Result<(
        Option<SubscriptionMetadata>,
        u16,
        bool,
        Option<Digest>,
        Option<Digest>,
        Option<FailureEvidence>,
    )> {
        let mut cursor = None;
        let mut seen = BTreeSet::new();
        let mut pages = 0_u16;
        let mut complete = false;
        let mut page_digests = Vec::new();
        let mut target = None;
        let mut final_cursor = None;
        while pages < request.max_pages {
            let page_request = GetAnomalySubscriptionsRequest::new(
                self.scope(),
                request.subscription_filter.clone(),
                cursor.clone(),
            )?;
            if let Some(cursor) = page_request.cursor() {
                if !seen.insert(cursor.token_digest().clone()) {
                    return Ok((
                        target,
                        pages,
                        false,
                        nonempty_digest(&page_digests),
                        final_cursor,
                        Some(FailureEvidence::pagination_loop(
                            AwsCostAnomalyOperation::GetAnomalySubscriptions,
                        )),
                    ));
                }
            }
            let response = match self.read_anomaly_subscriptions(&page_request) {
                Ok(response) => response,
                Err(AwsCostAnomalyError::Transport(error)) => {
                    let failure = FailureEvidence::from_transport(
                        AwsCostAnomalyOperation::GetAnomalySubscriptions,
                        &error,
                    );
                    return Ok((
                        target,
                        pages,
                        false,
                        nonempty_digest(&page_digests),
                        final_cursor,
                        Some(failure),
                    ));
                }
                Err(error) => return Err(error),
            };
            pages = pages.saturating_add(1);
            page_digests.push(response.evidence_digest.clone());
            for candidate in response.subscriptions {
                if candidate.arn() == self.scope().subscription() {
                    target = Some(candidate);
                }
            }
            if let Some(next) = response.next_cursor {
                final_cursor = Some(next.token_digest().clone());
                cursor = Some(next);
            } else {
                complete = true;
                break;
            }
        }
        if !complete {
            final_cursor = cursor.map(|cursor| cursor.token_digest().clone());
        }
        Ok((
            target,
            pages,
            complete,
            nonempty_digest(&page_digests),
            final_cursor,
            None,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn proposal_with(
        &self,
        request: &AwsCostAnomalyEvidenceRequest,
        state: AnomalyEvidenceState,
        pages: (u16, u16, u16),
        complete: (bool, bool, bool),
        digests: (Option<Digest>, Option<Digest>, Option<Digest>),
        cursor_digest: Option<Digest>,
        anomaly: Option<&AnomalyMetadata>,
        monitor: Option<&MonitorMetadata>,
        subscription: Option<&SubscriptionMetadata>,
        failure: Option<FailureEvidence>,
    ) -> AwsCostAnomalyProposal {
        AwsCostAnomalyProposal::new(
            &self.registration,
            self.provider.definition(),
            request,
            state,
            pages,
            complete,
            digests,
            cursor_digest,
            anomaly,
            monitor,
            subscription,
            failure,
            self.provider.provenance(),
        )
    }
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= crate::MAX_IDENTIFIER_BYTES
        && value.trim() == value
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn nonempty_digest(values: &[Digest]) -> Option<Digest> {
    (!values.is_empty()).then(|| {
        Digest::from_parts(
            "aws-cost-anomaly-page-digests/v1",
            &[(
                "pages",
                values
                    .iter()
                    .map(|digest| digest.as_str().to_owned())
                    .collect::<Vec<_>>()
                    .join("\n"),
            )],
        )
    })
}

fn state_from_failure(failure: &FailureEvidence) -> AnomalyEvidenceState {
    match failure.category.as_str() {
        "access_loss" | "unauthorized" | "forbidden" => AnomalyEvidenceState::AccessLoss,
        "throttled" => AnomalyEvidenceState::Throttled,
        "partial" | "pagination_loop" => AnomalyEvidenceState::Partial,
        "not_found" => AnomalyEvidenceState::NotFound,
        "retention_expired" => AnomalyEvidenceState::RetentionExpired,
        _ => AnomalyEvidenceState::ProviderUnknown,
    }
}

fn calculate_evidence_digest(proposal: &AwsCostAnomalyProposal) -> Digest {
    Digest::from_parts(
        "aws-cost-anomaly-evidence/v1",
        &[
            (
                "plugin_version",
                proposal.evidence.plugin_version_digest.as_str().to_owned(),
            ),
            (
                "contract",
                proposal.evidence.contract_digest.as_str().to_owned(),
            ),
            (
                "provider",
                proposal.evidence.provider_digest.as_str().to_owned(),
            ),
            (
                "monitor",
                proposal.evidence.monitor_digest.as_str().to_owned(),
            ),
            (
                "permission",
                proposal.evidence.permission_digest.as_str().to_owned(),
            ),
            (
                "consent",
                proposal.evidence.consent_digest.as_str().to_owned(),
            ),
            ("scope", proposal.evidence.scope_digest.as_str().to_owned()),
            (
                "filter",
                proposal.evidence.filter_digest.as_str().to_owned(),
            ),
            (
                "cursor",
                proposal
                    .evidence
                    .cursor_digest
                    .as_ref()
                    .map_or_else(String::new, |digest| digest.as_str().to_owned()),
            ),
            (
                "anomalies",
                proposal
                    .evidence
                    .anomalies_digest
                    .as_ref()
                    .map_or_else(String::new, |digest| digest.as_str().to_owned()),
            ),
            (
                "monitors",
                proposal
                    .evidence
                    .monitors_digest
                    .as_ref()
                    .map_or_else(String::new, |digest| digest.as_str().to_owned()),
            ),
            (
                "subscriptions",
                proposal
                    .evidence
                    .subscriptions_digest
                    .as_ref()
                    .map_or_else(String::new, |digest| digest.as_str().to_owned()),
            ),
            ("state", format!("{:?}", proposal.state)),
            ("anomaly_pages", proposal.anomaly_pages.to_string()),
            ("monitor_pages", proposal.monitor_pages.to_string()),
            (
                "subscription_pages",
                proposal.subscription_pages.to_string(),
            ),
            ("anomaly_complete", proposal.anomaly_complete.to_string()),
            ("monitor_complete", proposal.monitor_complete.to_string()),
            (
                "subscription_complete",
                proposal.subscription_complete.to_string(),
            ),
            (
                "anomaly",
                proposal.anomaly.as_ref().map_or_else(String::new, |value| {
                    serde_json::to_string(value).expect("projection serializes")
                }),
            ),
            (
                "monitor_projection",
                proposal.monitor.as_ref().map_or_else(String::new, |value| {
                    serde_json::to_string(value).expect("projection serializes")
                }),
            ),
            (
                "subscription_projection",
                proposal
                    .subscription
                    .as_ref()
                    .map_or_else(String::new, |value| {
                        serde_json::to_string(value).expect("projection serializes")
                    }),
            ),
            (
                "failure",
                proposal.failure.as_ref().map_or_else(String::new, |value| {
                    serde_json::to_string(value).expect("failure serializes")
                }),
            ),
            ("provenance", proposal.provenance.as_str().to_owned()),
        ],
    )
}
