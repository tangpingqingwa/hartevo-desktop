use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::consumer::MissionAzureEventHubPostureConsumer;
use crate::error::{AzureEventHubPostureResultError, AzureEventHubTransportError, Result};
use crate::model::{
    AzureEventHubEvidenceState, AzureEventHubPostureProjection, AzureEventHubPostureScope,
    ConsentScope, ConsumerGroupPostureProjection, CostReceipt, CostSummary, Digest,
    EventHubPostureProjection, EvidenceDigests, MissionProjection, NamespacePostureProjection,
    PermissionSnapshot, ProjectProjection, RequestReceipt, SecretReference, TransportProvenance,
    WorkProductProjection, mission_projection, project_projection, validate_page_size,
    work_product_projection,
};
use crate::provider::{
    AzureEventHubOperation, AzureEventHubsProvider, AzureEventHubsProviderDefinition,
    AzureEventHubsTransport, GetConsumerGroupRequest, GetEventHubRequest, GetNamespaceRequest,
    ListConsumerGroupsRequest,
};
use crate::{
    API_REVISION, CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_VERSION, MAX_PAGE_SIZE, MAX_PAGES,
    PLUGIN_VERSION, PROVIDER_ID, SERVICE_ID, contract_digest,
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
            "azure-event-hub-registration-transition/v1",
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

#[derive(Clone, Eq, PartialEq)]
pub struct AzureEventHubPostureRegistration {
    id: String,
    plugin_version: String,
    version_digest: Digest,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    provider_revision: u64,
    provider_release: String,
    provider_digest: Digest,
    api_digest: Digest,
    permission_snapshot: PermissionSnapshot,
    consent: ConsentScope,
    scope: AzureEventHubPostureScope,
    scope_digest: Digest,
    secret_reference: SecretReference,
    registration_revision: u64,
    status: RegistrationStatus,
    binding_digest: Digest,
}

impl AzureEventHubPostureRegistration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        scope: AzureEventHubPostureScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        consent: ConsentScope,
        provider: &AzureEventHubsProviderDefinition,
        registration_revision: u64,
    ) -> Result<Self> {
        let mut registration = Self {
            id: id.into(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: Digest::parse(CONTRACT_DIGEST.to_owned())?,
            provider_id: provider.provider_id.clone(),
            provider_revision: provider.provider_revision,
            provider_release: provider.release.clone(),
            provider_digest: provider.provider_digest.clone(),
            api_digest: Digest::from_text(API_REVISION),
            permission_snapshot,
            consent,
            scope_digest: scope.digest(),
            scope,
            secret_reference,
            registration_revision,
            status: RegistrationStatus::Active,
            binding_digest: Digest::from_text("unsealed-azure-event-hub-registration"),
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

    pub fn version_digest(&self) -> &Digest {
        &self.version_digest
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

    pub fn api_digest(&self) -> &Digest {
        &self.api_digest
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

    pub fn scope(&self) -> &AzureEventHubPostureScope {
        &self.scope
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    pub fn revoke_secret_reference(&mut self) -> Result<()> {
        self.secret_reference.revoke();
        self.binding_digest = self.calculate_binding_digest();
        self.validate()
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

    pub const fn is_reversible() -> bool {
        true
    }

    pub const fn is_revocable() -> bool {
        true
    }

    pub fn validate(&self) -> Result<()> {
        if !valid_registration_id(&self.id)
            || self.plugin_version != PLUGIN_VERSION
            || self.version_digest != Digest::from_text(PLUGIN_VERSION)
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest.as_str() != CONTRACT_DIGEST
            || self.contract_digest.as_str() != contract_digest().as_str()
            || self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.provider_release.is_empty()
            || self.api_digest != Digest::from_text(API_REVISION)
            || self.registration_revision == 0
            || self.scope_digest != self.scope.digest()
            || self.binding_digest != self.calculate_binding_digest()
        {
            return Err(AzureEventHubPostureResultError::InvalidRegistration);
        }
        self.permission_snapshot.validate()?;
        self.scope.validate()?;
        self.secret_reference.validate_binding(&self.scope)?;
        if self
            .permission_snapshot
            .permissions
            .iter()
            .any(|permission| !self.consent.permissions().contains(permission))
        {
            return Err(AzureEventHubPostureResultError::InvalidConsent);
        }
        self.consent.validate()
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AzureEventHubPostureResultError::RegistrationReversed);
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
            return Err(AzureEventHubPostureResultError::RegistrationReversed);
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
            return Err(AzureEventHubPostureResultError::RegistrationReversed);
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

    fn calculate_binding_digest(&self) -> Digest {
        Digest::from_parts(
            "azure-event-hub-registration/v1",
            &[
                ("id", self.id.clone()),
                ("plugin_version", self.plugin_version.clone()),
                ("version", self.version_digest.as_str().to_owned()),
                ("contract_version", self.contract_version.clone()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider_id", self.provider_id.clone()),
                ("provider_revision", self.provider_revision.to_string()),
                ("provider_release", self.provider_release.clone()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("api", self.api_digest.as_str().to_owned()),
                ("tenant", self.scope.tenant_digest().as_str().to_owned()),
                (
                    "subscription",
                    self.scope.subscription_digest().as_str().to_owned(),
                ),
                (
                    "resource_group",
                    self.scope.resource_group_digest().as_str().to_owned(),
                ),
                (
                    "namespace",
                    self.scope.namespace_digest().as_str().to_owned(),
                ),
                (
                    "event_hub",
                    self.scope.event_hub_digest().as_str().to_owned(),
                ),
                (
                    "consumer_group",
                    self.scope.consumer_group_digest().as_str().to_owned(),
                ),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("permission", self.permission_digest().as_str().to_owned()),
                ("consent", self.consent_digest().as_str().to_owned()),
                (
                    "secret",
                    self.secret_reference.reference_digest().as_str().to_owned(),
                ),
                (
                    "secret_revoked",
                    self.secret_reference.is_revoked().to_string(),
                ),
                ("revision", self.registration_revision.to_string()),
                ("status", format!("{:?}", self.status)),
            ],
        )
    }
}

pub type AzureEventHubRegistration = AzureEventHubPostureRegistration;

impl fmt::Debug for AzureEventHubPostureRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AzureEventHubPostureRegistration")
            .field("id_digest", &Digest::from_text(&self.id))
            .field("plugin_version", &self.plugin_version)
            .field("version_digest", &self.version_digest)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider_id", &self.provider_id)
            .field("provider_revision", &self.provider_revision)
            .field("provider_digest", &self.provider_digest)
            .field("api_digest", &self.api_digest)
            .field("permission_digest", &self.permission_digest())
            .field("consent_digest", &self.consent_digest())
            .field("scope_digest", &self.scope_digest)
            .field("secret_reference_digest", &self.secret_reference_digest())
            .field("registration_revision", &self.registration_revision)
            .field("status", &self.status)
            .field("registration_digest", &self.binding_digest)
            .finish()
    }
}

impl Serialize for AzureEventHubPostureRegistration {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AzureEventHubPostureRegistration", 22)?;
        state.serialize_field("idDigest", &Digest::from_text(&self.id))?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("versionDigest", &self.version_digest)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("providerRelease", &self.provider_release)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("apiDigest", &self.api_digest)?;
        state.serialize_field("permissionDigest", &self.permission_digest())?;
        state.serialize_field("consentDigest", &self.consent_digest())?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("secretReferenceDigest", &self.secret_reference_digest())?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("reversible", &true)?;
        state.serialize_field("revocable", &true)?;
        state.serialize_field("registrationDigest", &self.binding_digest)?;
        state.end()
    }
}

fn valid_registration_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= crate::MAX_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityDescription {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub api_revision: String,
    pub operations: Vec<String>,
    pub permissions: Vec<String>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub outcome_adoption: bool,
    pub work_product_adoption: bool,
    pub data_plane: bool,
    pub mutations: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AzureEventHubPostureEvidenceRequest {
    pub scope_digest: Digest,
    pub page_size: u16,
    pub max_pages: u16,
    pub expected_provider_digest: Digest,
    pub expected_registration_digest: Digest,
    pub observed_at: DateTime<Utc>,
    pub request_digest: Digest,
}

impl AzureEventHubPostureEvidenceRequest {
    pub fn new(
        scope: &AzureEventHubPostureScope,
        page_size: u16,
        max_pages: u16,
        expected_provider_digest: Digest,
        expected_registration_digest: Digest,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        validate_page_size(page_size)?;
        if max_pages == 0 || max_pages > MAX_PAGES {
            return Err(AzureEventHubPostureResultError::InvalidRequest);
        }
        expected_provider_digest.validate()?;
        expected_registration_digest.validate()?;
        scope.validate()?;
        let mut request = Self {
            scope_digest: scope.digest(),
            page_size,
            max_pages,
            expected_provider_digest,
            expected_registration_digest,
            observed_at,
            request_digest: Digest::from_text("unsealed-azure-event-hub-evidence-request"),
        };
        request.request_digest = request.calculate_digest();
        Ok(request)
    }

    pub fn digest(&self) -> &Digest {
        &self.request_digest
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "azure-event-hub-evidence-request/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("page_size", self.page_size.to_string()),
                ("max_pages", self.max_pages.to_string()),
                (
                    "provider",
                    self.expected_provider_digest.as_str().to_owned(),
                ),
                (
                    "registration",
                    self.expected_registration_digest.as_str().to_owned(),
                ),
                ("observed_at", self.observed_at.to_rfc3339()),
            ],
        )
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.scope_digest.validate()?;
        self.expected_provider_digest.validate()?;
        self.expected_registration_digest.validate()?;
        if self.page_size == 0
            || self.page_size > MAX_PAGE_SIZE
            || self.max_pages == 0
            || self.max_pages > MAX_PAGES
            || self.request_digest != self.calculate_digest()
        {
            return Err(AzureEventHubPostureResultError::TamperedEvidence);
        }
        Ok(())
    }
}

pub type AzureEventHubPostureRequest = AzureEventHubPostureEvidenceRequest;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailureEvidence {
    pub operation: AzureEventHubOperation,
    pub status_code: Option<u16>,
    pub category: String,
    pub failure_digest: Digest,
}

impl FailureEvidence {
    fn from_transport(
        operation: AzureEventHubOperation,
        error: &AzureEventHubTransportError,
    ) -> Self {
        let category = match error {
            AzureEventHubTransportError::BlockedEnv => "provider_unknown",
            AzureEventHubTransportError::BadRequest => "provider_unknown",
            AzureEventHubTransportError::Unauthorized => "unauthorized",
            AzureEventHubTransportError::Forbidden => "forbidden",
            AzureEventHubTransportError::NotFound => "not_found",
            AzureEventHubTransportError::Conflict => "conflict",
            AzureEventHubTransportError::RateLimited { .. } => "throttled",
            AzureEventHubTransportError::ServerError { .. } => "provider_unknown",
            AzureEventHubTransportError::Timeout => "timed_out",
            AzureEventHubTransportError::AccessLost => "access_loss",
            AzureEventHubTransportError::Partial => "partial",
            AzureEventHubTransportError::Unknown => "provider_unknown",
            AzureEventHubTransportError::InvalidResponse => "provider_unknown",
            AzureEventHubTransportError::Tampered => "tampered",
            AzureEventHubTransportError::ApiDrift => "api_drift",
            AzureEventHubTransportError::ScopeDrift => "scope_drift",
            AzureEventHubTransportError::StaleState => "stale_state",
            AzureEventHubTransportError::PaginationLoop => "pagination_loop",
            AzureEventHubTransportError::Revoked => "registration_revoked",
        }
        .to_owned();
        let failure_digest = Digest::from_parts(
            "azure-event-hub-failure/v1",
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
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AzureEventHubPostureProposal {
    pub service_id: String,
    pub consumer_id: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub tenant_digest: Digest,
    pub subscription_digest: Digest,
    pub resource_group_digest: Digest,
    pub namespace_digest: Digest,
    pub event_hub_digest: Digest,
    pub consumer_group_digest: Digest,
    pub mission: MissionProjection,
    pub project: ProjectProjection,
    pub work_product: WorkProductProjection,
    pub state: AzureEventHubEvidenceState,
    pub list_pages: u16,
    pub list_complete: bool,
    pub namespace: Option<NamespacePostureProjection>,
    pub event_hub: Option<EventHubPostureProjection>,
    pub consumer_group: Option<ConsumerGroupPostureProjection>,
    pub posture: Option<AzureEventHubPostureProjection>,
    pub failure: Option<FailureEvidence>,
    pub request_receipts: Vec<RequestReceipt>,
    pub cost_receipts: Vec<CostReceipt>,
    pub cost_summary: CostSummary,
    pub evidence: EvidenceDigests,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub availability_claim: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub proposal_digest: Digest,
}

impl AzureEventHubPostureProposal {
    #[allow(clippy::too_many_arguments)]
    fn new(
        registration: &AzureEventHubPostureRegistration,
        provider: &AzureEventHubsProviderDefinition,
        request: &AzureEventHubPostureEvidenceRequest,
        state: AzureEventHubEvidenceState,
        list_pages: u16,
        list_complete: bool,
        list_digest: Option<Digest>,
        namespace_get_digest: Option<Digest>,
        event_hub_get_digest: Option<Digest>,
        consumer_group_get_digest: Option<Digest>,
        namespace: Option<NamespacePostureProjection>,
        event_hub: Option<EventHubPostureProjection>,
        consumer_group: Option<ConsumerGroupPostureProjection>,
        posture: Option<AzureEventHubPostureProjection>,
        failure: Option<FailureEvidence>,
        request_receipts: Vec<RequestReceipt>,
        cost_receipts: Vec<CostReceipt>,
        provenance: TransportProvenance,
    ) -> Self {
        let scope = registration.scope();
        let mut evidence = EvidenceDigests {
            plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_digest: registration.contract_digest.clone(),
            provider_digest: provider.provider_digest.clone(),
            api_digest: registration.api_digest.clone(),
            permission_digest: registration.permission_digest(),
            consent_digest: registration.consent_digest(),
            scope_digest: registration.scope_digest.clone(),
            tenant_digest: scope.tenant_digest(),
            subscription_digest: scope.subscription_digest(),
            resource_group_digest: scope.resource_group_digest(),
            namespace_digest: scope.namespace_digest(),
            event_hub_digest: scope.event_hub_digest(),
            consumer_group_digest: scope.consumer_group_digest(),
            list_consumer_groups_digest: list_digest,
            namespace_get_digest,
            event_hub_get_digest,
            consumer_group_get_digest,
            evidence_digest: Digest::from_text("unsealed-azure-event-hub-evidence"),
        };
        evidence.evidence_digest = calculate_evidence_digest(
            &evidence,
            request.digest(),
            state,
            list_pages,
            list_complete,
            posture.as_ref(),
            failure.as_ref(),
            &request_receipts,
            &cost_receipts,
        );
        let cost_summary = CostSummary::from_receipts(&cost_receipts);
        let mut proposal = Self {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            registration_digest: registration.registration_digest().clone(),
            scope_digest: registration.scope_digest.clone(),
            request_digest: request.digest().clone(),
            tenant_digest: scope.tenant_digest(),
            subscription_digest: scope.subscription_digest(),
            resource_group_digest: scope.resource_group_digest(),
            namespace_digest: scope.namespace_digest(),
            event_hub_digest: scope.event_hub_digest(),
            consumer_group_digest: scope.consumer_group_digest(),
            mission: mission_projection(scope.mission()),
            project: project_projection(scope.project()),
            work_product: work_product_projection(scope.work_product()),
            state,
            list_pages,
            list_complete,
            namespace,
            event_hub,
            consumer_group,
            posture,
            failure,
            request_receipts,
            cost_receipts,
            cost_summary,
            evidence,
            provenance,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            availability_claim: false,
            outcome_adopted: false,
            work_product_adopted: false,
            proposal_digest: Digest::from_text("unsealed-azure-event-hub-proposal"),
        };
        proposal.proposal_digest = proposal.calculate_digest();
        proposal
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.evidence.validate()?;
        self.request_digest.validate()?;
        for receipt in &self.request_receipts {
            receipt.validate_integrity()?;
        }
        for receipt in &self.cost_receipts {
            receipt.validate_integrity()?;
        }
        if self.service_id != SERVICE_ID
            || self.consumer_id != CONSUMER_ID
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.availability_claim
            || self.outcome_adopted
            || self.work_product_adopted
            || self.cost_summary.cost_digest
                != CostSummary::from_receipts(&self.cost_receipts).cost_digest
            || self.evidence.evidence_digest
                != calculate_evidence_digest(
                    &self.evidence,
                    &self.request_digest,
                    self.state,
                    self.list_pages,
                    self.list_complete,
                    self.posture.as_ref(),
                    self.failure.as_ref(),
                    &self.request_receipts,
                    &self.cost_receipts,
                )
            || self.proposal_digest != self.calculate_digest()
        {
            return Err(AzureEventHubPostureResultError::TamperedEvidence);
        }
        if let Some(namespace) = &self.namespace {
            namespace.validate_integrity()?;
            if namespace.namespace_identity_digest != self.namespace_digest {
                return Err(AzureEventHubPostureResultError::ScopeMismatch);
            }
        }
        if let Some(event_hub) = &self.event_hub {
            event_hub.validate_integrity()?;
            if event_hub.event_hub_identity_digest != self.event_hub_digest {
                return Err(AzureEventHubPostureResultError::ScopeMismatch);
            }
        }
        if let Some(consumer_group) = &self.consumer_group {
            consumer_group.validate_integrity()?;
            if consumer_group.consumer_group_identity_digest != self.consumer_group_digest {
                return Err(AzureEventHubPostureResultError::ScopeMismatch);
            }
        }
        if let Some(posture) = &self.posture {
            posture.validate_integrity()?;
            if self.namespace.as_ref() != Some(&posture.namespace)
                || self.event_hub.as_ref() != Some(&posture.event_hub)
                || self.consumer_group.as_ref() != Some(&posture.consumer_group)
            {
                return Err(AzureEventHubPostureResultError::TamperedEvidence);
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> &Digest {
        &self.proposal_digest
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub const fn is_review_only(&self) -> bool {
        true
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "azure-event-hub-posture-proposal/v1",
            &[
                ("service", self.service_id.clone()),
                ("consumer", self.consumer_id.clone()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("tenant", self.tenant_digest.as_str().to_owned()),
                ("subscription", self.subscription_digest.as_str().to_owned()),
                (
                    "resource_group",
                    self.resource_group_digest.as_str().to_owned(),
                ),
                ("namespace", self.namespace_digest.as_str().to_owned()),
                ("event_hub", self.event_hub_digest.as_str().to_owned()),
                (
                    "consumer_group",
                    self.consumer_group_digest.as_str().to_owned(),
                ),
                (
                    "mission",
                    serde_json::to_string(&self.mission).expect("mission serializes"),
                ),
                (
                    "project",
                    serde_json::to_string(&self.project).expect("project serializes"),
                ),
                (
                    "work_product",
                    serde_json::to_string(&self.work_product).expect("work product serializes"),
                ),
                ("state", format!("{:?}", self.state)),
                ("list_pages", self.list_pages.to_string()),
                ("list_complete", self.list_complete.to_string()),
                (
                    "namespace_projection",
                    self.namespace.as_ref().map_or_else(String::new, |value| {
                        serde_json::to_string(value).expect("namespace serializes")
                    }),
                ),
                (
                    "event_hub_projection",
                    self.event_hub.as_ref().map_or_else(String::new, |value| {
                        serde_json::to_string(value).expect("event hub serializes")
                    }),
                ),
                (
                    "consumer_group_projection",
                    self.consumer_group
                        .as_ref()
                        .map_or_else(String::new, |value| {
                            serde_json::to_string(value).expect("consumer group serializes")
                        }),
                ),
                (
                    "posture",
                    self.posture.as_ref().map_or_else(String::new, |value| {
                        serde_json::to_string(value).expect("posture serializes")
                    }),
                ),
                (
                    "failure",
                    self.failure.as_ref().map_or_else(String::new, |value| {
                        serde_json::to_string(value).expect("failure serializes")
                    }),
                ),
                (
                    "requests",
                    self.request_receipts
                        .iter()
                        .map(|receipt| receipt.receipt_digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                (
                    "costs",
                    self.cost_receipts
                        .iter()
                        .map(|receipt| receipt.receipt_digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                (
                    "evidence",
                    serde_json::to_string(&self.evidence).expect("evidence serializes"),
                ),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

fn calculate_evidence_digest(
    evidence: &EvidenceDigests,
    request_digest: &Digest,
    state: AzureEventHubEvidenceState,
    list_pages: u16,
    list_complete: bool,
    posture: Option<&AzureEventHubPostureProjection>,
    failure: Option<&FailureEvidence>,
    request_receipts: &[RequestReceipt],
    cost_receipts: &[CostReceipt],
) -> Digest {
    Digest::from_parts(
        "azure-event-hub-evidence/v1",
        &[
            ("plugin", evidence.plugin_version_digest.as_str().to_owned()),
            ("contract", evidence.contract_digest.as_str().to_owned()),
            ("provider", evidence.provider_digest.as_str().to_owned()),
            ("api", evidence.api_digest.as_str().to_owned()),
            ("permission", evidence.permission_digest.as_str().to_owned()),
            ("consent", evidence.consent_digest.as_str().to_owned()),
            ("scope", evidence.scope_digest.as_str().to_owned()),
            ("tenant", evidence.tenant_digest.as_str().to_owned()),
            (
                "subscription",
                evidence.subscription_digest.as_str().to_owned(),
            ),
            (
                "resource_group",
                evidence.resource_group_digest.as_str().to_owned(),
            ),
            ("namespace", evidence.namespace_digest.as_str().to_owned()),
            ("event_hub", evidence.event_hub_digest.as_str().to_owned()),
            (
                "consumer_group",
                evidence.consumer_group_digest.as_str().to_owned(),
            ),
            (
                "list",
                evidence
                    .list_consumer_groups_digest
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
            ),
            (
                "namespace_get",
                evidence
                    .namespace_get_digest
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
            ),
            (
                "event_hub_get",
                evidence
                    .event_hub_get_digest
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
            ),
            (
                "consumer_group_get",
                evidence
                    .consumer_group_get_digest
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
            ),
            ("request", request_digest.as_str().to_owned()),
            ("state", format!("{state:?}")),
            ("list_pages", list_pages.to_string()),
            ("list_complete", list_complete.to_string()),
            (
                "posture",
                posture.map_or_else(String::new, |value| {
                    value.posture_digest.as_str().to_owned()
                }),
            ),
            (
                "failure",
                failure.map_or_else(String::new, |value| {
                    value.failure_digest.as_str().to_owned()
                }),
            ),
            (
                "requests",
                request_receipts
                    .iter()
                    .map(|receipt| receipt.receipt_digest.as_str().to_owned())
                    .collect::<Vec<_>>()
                    .join("\n"),
            ),
            (
                "costs",
                cost_receipts
                    .iter()
                    .map(|receipt| receipt.receipt_digest.as_str().to_owned())
                    .collect::<Vec<_>>()
                    .join("\n"),
            ),
        ],
    )
}

pub struct AzureEventHubPostureResultService<T: AzureEventHubsTransport> {
    registration: AzureEventHubPostureRegistration,
    provider: AzureEventHubsProvider<T>,
}

impl<T: AzureEventHubsTransport> fmt::Debug for AzureEventHubPostureResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AzureEventHubPostureResultService")
            .field("registration", &self.registration)
            .field("provider", &self.provider)
            .finish()
    }
}

impl<T: AzureEventHubsTransport> AzureEventHubPostureResultService<T> {
    pub const fn registration_reversible() -> bool {
        true
    }

    pub const fn registration_revocable() -> bool {
        true
    }

    pub fn new(
        scope: AzureEventHubPostureScope,
        secret_reference: SecretReference,
        consent: ConsentScope,
        provider: AzureEventHubsProvider<T>,
        _observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        if secret_reference.is_revoked() {
            return Err(AzureEventHubPostureResultError::SecretRevoked);
        }
        let registration = AzureEventHubPostureRegistration::new(
            "azure-event-hub-posture-registration",
            scope,
            secret_reference,
            PermissionSnapshot::for_layer_one(1),
            consent,
            provider.definition(),
            1,
        )?;
        Ok(Self {
            registration,
            provider,
        })
    }

    pub fn register(
        scope: AzureEventHubPostureScope,
        secret_reference: SecretReference,
        consent: ConsentScope,
        provider: AzureEventHubsProvider<T>,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        Self::new(scope, secret_reference, consent, provider, observed_at)
    }

    pub fn with_registration(
        registration: AzureEventHubPostureRegistration,
        provider: AzureEventHubsProvider<T>,
    ) -> Result<Self> {
        registration.validate()?;
        if registration.secret_reference().is_revoked() {
            return Err(AzureEventHubPostureResultError::SecretRevoked);
        }
        provider.definition().validate()?;
        if registration.provider_digest() != &provider.definition().provider_digest {
            return Err(AzureEventHubPostureResultError::ProviderDrift);
        }
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
            api_revision: API_REVISION.to_owned(),
            operations: vec![
                AzureEventHubOperation::GetNamespace.as_str().to_owned(),
                AzureEventHubOperation::GetEventHub.as_str().to_owned(),
                AzureEventHubOperation::GetConsumerGroup.as_str().to_owned(),
                AzureEventHubOperation::ListConsumerGroups
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
            work_product_adoption: false,
            data_plane: false,
            mutations: false,
        }
    }

    pub fn scope(&self) -> &AzureEventHubPostureScope {
        self.registration.scope()
    }

    pub fn registration(&self) -> &AzureEventHubPostureRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut AzureEventHubPostureRegistration {
        &mut self.registration
    }

    pub fn provider(&self) -> &AzureEventHubsProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AzureEventHubsProvider<T> {
        &mut self.provider
    }

    pub fn default_request(
        &self,
        observed_at: DateTime<Utc>,
    ) -> Result<AzureEventHubPostureEvidenceRequest> {
        self.request(crate::MAX_PAGE_SIZE, MAX_PAGES, observed_at)
    }

    pub fn request(
        &self,
        page_size: u16,
        max_pages: u16,
        observed_at: DateTime<Utc>,
    ) -> Result<AzureEventHubPostureEvidenceRequest> {
        AzureEventHubPostureEvidenceRequest::new(
            self.scope(),
            page_size,
            max_pages,
            self.provider.definition().provider_digest.clone(),
            self.registration.registration_digest().clone(),
            observed_at,
        )
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

    pub fn revoke_secret_reference(&mut self) -> Result<()> {
        self.registration.revoke_secret_reference()
    }

    pub fn consumer(&self) -> Result<MissionAzureEventHubPostureConsumer> {
        MissionAzureEventHubPostureConsumer::new(self.scope().clone(), self.registration.clone())
    }

    pub fn verify(&self, proposal: &AzureEventHubPostureProposal) -> VerificationReport {
        let mut failures = Vec::new();
        if !self.registration.is_active() {
            failures.push(VerificationFailure::RegistrationInactive);
        }
        if proposal.registration_digest != *self.registration.registration_digest() {
            failures.push(VerificationFailure::RegistrationDigestMismatch);
        }
        if proposal.evidence.contract_digest != *self.registration.contract_digest() {
            failures.push(VerificationFailure::ContractDigestMismatch);
        }
        if proposal.evidence.provider_digest != self.provider.definition().provider_digest {
            failures.push(VerificationFailure::ProviderDigestMismatch);
        }
        if proposal.evidence.permission_digest != self.registration.permission_digest() {
            failures.push(VerificationFailure::PermissionDigestMismatch);
        }
        if proposal.evidence.scope_digest != *self.registration.scope_digest() {
            failures.push(VerificationFailure::ScopeDigestMismatch);
        }
        if proposal.evidence.api_digest != *self.registration.api_digest() {
            failures.push(VerificationFailure::ApiDigestMismatch);
        }
        if proposal.validate_integrity().is_err() {
            failures.push(VerificationFailure::TamperedEvidence);
        }
        match proposal.state {
            AzureEventHubEvidenceState::Partial => {
                failures.push(VerificationFailure::PartialEvidence);
            }
            AzureEventHubEvidenceState::StaleState => {
                failures.push(VerificationFailure::StaleState);
            }
            AzureEventHubEvidenceState::AccessLoss => {
                failures.push(VerificationFailure::AccessLoss);
            }
            AzureEventHubEvidenceState::Unauthorized => {
                failures.push(VerificationFailure::Unauthorized);
            }
            AzureEventHubEvidenceState::Forbidden => failures.push(VerificationFailure::Forbidden),
            AzureEventHubEvidenceState::NotFound => failures.push(VerificationFailure::NotFound),
            AzureEventHubEvidenceState::Conflict => failures.push(VerificationFailure::Conflict),
            AzureEventHubEvidenceState::Throttled => failures.push(VerificationFailure::Throttled),
            AzureEventHubEvidenceState::TimedOut => failures.push(VerificationFailure::TimedOut),
            AzureEventHubEvidenceState::ApiDrift => failures.push(VerificationFailure::ApiDrift),
            AzureEventHubEvidenceState::ScopeDrift => {
                failures.push(VerificationFailure::ScopeDrift);
            }
            AzureEventHubEvidenceState::PaginationLoop => {
                failures.push(VerificationFailure::PaginationLoop);
            }
            AzureEventHubEvidenceState::Tampered => {
                failures.push(VerificationFailure::TamperedEvidence);
            }
            AzureEventHubEvidenceState::ProviderUnknown => {
                failures.push(VerificationFailure::ProviderUnknown);
            }
            AzureEventHubEvidenceState::RegistrationRevoked => {
                failures.push(VerificationFailure::RegistrationInactive);
            }
            AzureEventHubEvidenceState::Ready
            | AzureEventHubEvidenceState::InProgress
            | AzureEventHubEvidenceState::Disabled => {}
        }
        failures.sort_unstable();
        failures.dedup();
        let valid = failures.is_empty();
        let review_eligible = valid
            && proposal.list_complete
            && proposal.posture.is_some()
            && proposal.state == AzureEventHubEvidenceState::Ready
            && !proposal.connected
            && !proposal.native
            && !proposal.first_party
            && !proposal.provider_receipt;
        VerificationReport::new(valid, review_eligible, failures)
    }

    pub fn propose(
        &mut self,
        request: AzureEventHubPostureEvidenceRequest,
    ) -> Result<AzureEventHubPostureProposal> {
        self.validate_request(&request)?;
        let mut list_request = ListConsumerGroupsRequest::first(self.scope(), request.page_size)?;
        let mut seen_cursors = BTreeSet::new();
        let mut request_receipts = Vec::new();
        let mut cost_receipts = Vec::new();
        let mut list_digests = Vec::new();
        let mut list_pages = list_request.page_number();
        let list_complete;
        let mut selected_group: Option<ConsumerGroupPostureProjection> = None;

        loop {
            match self.provider.list_consumer_groups(&list_request) {
                Ok(response) => {
                    request_receipts.push(response.request_receipt.clone());
                    cost_receipts.push(response.cost_receipt.clone());
                    list_digests.push(response.evidence_digest.clone());
                    for group in &response.consumer_groups {
                        if group.consumer_group_identity_digest
                            == self.scope().consumer_group_digest()
                        {
                            if selected_group.as_ref().is_some_and(|previous| {
                                previous.revision_digest != group.revision_digest
                            }) {
                                return Ok(self.failed_proposal(
                                    &request,
                                    AzureEventHubEvidenceState::StaleState,
                                    list_pages,
                                    false,
                                    Some(Digest::from_parts(
                                        "azure-event-hub-list-evidence/v1",
                                        &[("pages", crate::model::join_digests(list_digests))],
                                    )),
                                    None,
                                    None,
                                    None,
                                    None,
                                    Some(FailureEvidence::from_transport(
                                        AzureEventHubOperation::ListConsumerGroups,
                                        &AzureEventHubTransportError::StaleState,
                                    )),
                                    request_receipts,
                                    cost_receipts,
                                ));
                            }
                            selected_group = Some(group.clone());
                        }
                    }
                    if let Some(cursor) = response.next_cursor {
                        if !seen_cursors.insert(cursor.continuation_digest().clone()) {
                            return Ok(self.failed_proposal(
                                &request,
                                AzureEventHubEvidenceState::PaginationLoop,
                                list_pages,
                                false,
                                Some(Digest::from_parts(
                                    "azure-event-hub-list-evidence/v1",
                                    &[("pages", crate::model::join_digests(list_digests))],
                                )),
                                None,
                                None,
                                None,
                                None,
                                Some(FailureEvidence::from_transport(
                                    AzureEventHubOperation::ListConsumerGroups,
                                    &AzureEventHubTransportError::PaginationLoop,
                                )),
                                request_receipts,
                                cost_receipts,
                            ));
                        }
                        if list_pages >= request.max_pages {
                            return Ok(self.failed_proposal(
                                &request,
                                AzureEventHubEvidenceState::Partial,
                                list_pages,
                                false,
                                Some(Digest::from_parts(
                                    "azure-event-hub-list-evidence/v1",
                                    &[("pages", crate::model::join_digests(list_digests))],
                                )),
                                None,
                                None,
                                None,
                                None,
                                Some(FailureEvidence::from_transport(
                                    AzureEventHubOperation::ListConsumerGroups,
                                    &AzureEventHubTransportError::Partial,
                                )),
                                request_receipts,
                                cost_receipts,
                            ));
                        }
                        list_request = ListConsumerGroupsRequest::new(
                            self.scope(),
                            request.page_size,
                            Some(cursor),
                        )?;
                        list_pages = list_request.page_number();
                    } else {
                        list_complete = true;
                        break;
                    }
                }
                Err(error) => {
                    request_receipts.push(list_request.recorded_request().receipt(0)?);
                    cost_receipts.push(CostReceipt::new(
                        AzureEventHubOperation::ListConsumerGroups.as_str(),
                        0,
                    )?);
                    return Ok(self.failed_proposal(
                        &request,
                        state_for_transport(&error),
                        list_pages,
                        false,
                        (!list_digests.is_empty()).then(|| {
                            Digest::from_parts(
                                "azure-event-hub-list-evidence/v1",
                                &[("pages", crate::model::join_digests(list_digests))],
                            )
                        }),
                        None,
                        None,
                        None,
                        None,
                        Some(FailureEvidence::from_transport(
                            AzureEventHubOperation::ListConsumerGroups,
                            &error,
                        )),
                        request_receipts,
                        cost_receipts,
                    ));
                }
            }
        }

        let list_digest = Some(Digest::from_parts(
            "azure-event-hub-list-evidence/v1",
            &[("pages", crate::model::join_digests(list_digests))],
        ));
        let Some(listed_group) = selected_group else {
            return Ok(self.failed_proposal(
                &request,
                AzureEventHubEvidenceState::NotFound,
                list_pages,
                list_complete,
                list_digest,
                None,
                None,
                None,
                None,
                Some(FailureEvidence::from_transport(
                    AzureEventHubOperation::ListConsumerGroups,
                    &AzureEventHubTransportError::NotFound,
                )),
                request_receipts,
                cost_receipts,
            ));
        };

        let namespace_request = GetNamespaceRequest::for_scope(self.scope())?;
        let namespace_response = match self.provider.get_namespace(&namespace_request) {
            Ok(response) => response,
            Err(error) => {
                request_receipts.push(namespace_request.recorded_request().receipt(0)?);
                cost_receipts.push(CostReceipt::new(
                    AzureEventHubOperation::GetNamespace.as_str(),
                    0,
                )?);
                return Ok(self.failed_proposal(
                    &request,
                    state_for_transport(&error),
                    list_pages,
                    list_complete,
                    list_digest,
                    None,
                    None,
                    None,
                    None,
                    Some(FailureEvidence::from_transport(
                        AzureEventHubOperation::GetNamespace,
                        &error,
                    )),
                    request_receipts,
                    cost_receipts,
                ));
            }
        };
        request_receipts.push(namespace_response.request_receipt.clone());
        cost_receipts.push(namespace_response.cost_receipt.clone());
        if let Err(error) = validate_revision_fence(
            self.scope()
                .revision_fences()
                .namespace_revision_digest
                .as_ref(),
            &namespace_response.namespace.revision_digest,
        ) {
            return Ok(self.failed_proposal(
                &request,
                state_for_error(&error),
                list_pages,
                list_complete,
                list_digest,
                None,
                None,
                None,
                None,
                Some(FailureEvidence::from_transport(
                    AzureEventHubOperation::GetNamespace,
                    &error,
                )),
                request_receipts,
                cost_receipts,
            ));
        }

        let event_hub_request = GetEventHubRequest::for_scope(self.scope())?;
        let event_hub_response = match self.provider.get_event_hub(&event_hub_request) {
            Ok(response) => response,
            Err(error) => {
                request_receipts.push(event_hub_request.recorded_request().receipt(0)?);
                cost_receipts.push(CostReceipt::new(
                    AzureEventHubOperation::GetEventHub.as_str(),
                    0,
                )?);
                return Ok(self.failed_proposal(
                    &request,
                    state_for_transport(&error),
                    list_pages,
                    list_complete,
                    list_digest,
                    Some(namespace_response.evidence_digest.clone()),
                    None,
                    None,
                    None,
                    Some(FailureEvidence::from_transport(
                        AzureEventHubOperation::GetEventHub,
                        &error,
                    )),
                    request_receipts,
                    cost_receipts,
                ));
            }
        };
        request_receipts.push(event_hub_response.request_receipt.clone());
        cost_receipts.push(event_hub_response.cost_receipt.clone());
        if let Err(error) = validate_revision_fence(
            self.scope()
                .revision_fences()
                .event_hub_revision_digest
                .as_ref(),
            &event_hub_response.event_hub.revision_digest,
        ) {
            return Ok(self.failed_proposal(
                &request,
                state_for_error(&error),
                list_pages,
                list_complete,
                list_digest,
                Some(namespace_response.evidence_digest.clone()),
                None,
                None,
                None,
                Some(FailureEvidence::from_transport(
                    AzureEventHubOperation::GetEventHub,
                    &error,
                )),
                request_receipts,
                cost_receipts,
            ));
        }

        let consumer_group_request = GetConsumerGroupRequest::for_scope(self.scope())?;
        let consumer_group_response =
            match self.provider.get_consumer_group(&consumer_group_request) {
                Ok(response) => response,
                Err(error) => {
                    request_receipts.push(consumer_group_request.recorded_request().receipt(0)?);
                    cost_receipts.push(CostReceipt::new(
                        AzureEventHubOperation::GetConsumerGroup.as_str(),
                        0,
                    )?);
                    return Ok(self.failed_proposal(
                        &request,
                        state_for_transport(&error),
                        list_pages,
                        list_complete,
                        list_digest,
                        Some(namespace_response.evidence_digest.clone()),
                        Some(event_hub_response.evidence_digest.clone()),
                        None,
                        None,
                        Some(FailureEvidence::from_transport(
                            AzureEventHubOperation::GetConsumerGroup,
                            &error,
                        )),
                        request_receipts,
                        cost_receipts,
                    ));
                }
            };
        request_receipts.push(consumer_group_response.request_receipt.clone());
        cost_receipts.push(consumer_group_response.cost_receipt.clone());
        if let Err(error) = validate_revision_fence(
            self.scope()
                .revision_fences()
                .consumer_group_revision_digest
                .as_ref(),
            &consumer_group_response.consumer_group.revision_digest,
        ) {
            return Ok(self.failed_proposal(
                &request,
                state_for_error(&error),
                list_pages,
                list_complete,
                list_digest,
                Some(namespace_response.evidence_digest.clone()),
                Some(event_hub_response.evidence_digest.clone()),
                Some(consumer_group_response.evidence_digest.clone()),
                None,
                Some(FailureEvidence::from_transport(
                    AzureEventHubOperation::GetConsumerGroup,
                    &error,
                )),
                request_receipts,
                cost_receipts,
            ));
        }
        if listed_group.revision_digest != consumer_group_response.consumer_group.revision_digest {
            let error = AzureEventHubTransportError::StaleState;
            return Ok(self.failed_proposal(
                &request,
                AzureEventHubEvidenceState::StaleState,
                list_pages,
                list_complete,
                list_digest,
                Some(namespace_response.evidence_digest.clone()),
                Some(event_hub_response.evidence_digest.clone()),
                Some(consumer_group_response.evidence_digest.clone()),
                None,
                Some(FailureEvidence::from_transport(
                    AzureEventHubOperation::GetConsumerGroup,
                    &error,
                )),
                request_receipts,
                cost_receipts,
            ));
        }

        let namespace = namespace_response.namespace;
        let event_hub = event_hub_response.event_hub;
        let consumer_group = consumer_group_response.consumer_group;
        let posture = AzureEventHubPostureProjection::new(
            namespace.clone(),
            event_hub.clone(),
            consumer_group.clone(),
        )?;
        let state = posture_state(&posture);
        Ok(AzureEventHubPostureProposal::new(
            &self.registration,
            self.provider.definition(),
            &request,
            state,
            list_pages,
            list_complete,
            list_digest,
            Some(namespace_response.evidence_digest),
            Some(event_hub_response.evidence_digest),
            Some(consumer_group_response.evidence_digest),
            Some(namespace.clone()),
            Some(event_hub.clone()),
            Some(consumer_group.clone()),
            Some(posture),
            None,
            request_receipts,
            cost_receipts,
            self.provider.provenance(),
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn failed_proposal(
        &self,
        request: &AzureEventHubPostureEvidenceRequest,
        state: AzureEventHubEvidenceState,
        list_pages: u16,
        list_complete: bool,
        list_digest: Option<Digest>,
        namespace_get_digest: Option<Digest>,
        event_hub_get_digest: Option<Digest>,
        consumer_group_get_digest: Option<Digest>,
        posture: Option<AzureEventHubPostureProjection>,
        failure: Option<FailureEvidence>,
        request_receipts: Vec<RequestReceipt>,
        cost_receipts: Vec<CostReceipt>,
    ) -> AzureEventHubPostureProposal {
        AzureEventHubPostureProposal::new(
            &self.registration,
            self.provider.definition(),
            request,
            state,
            list_pages,
            list_complete,
            list_digest,
            namespace_get_digest,
            event_hub_get_digest,
            consumer_group_get_digest,
            None,
            None,
            None,
            posture,
            failure,
            request_receipts,
            cost_receipts,
            self.provider.provenance(),
        )
    }

    fn validate_request(&self, request: &AzureEventHubPostureEvidenceRequest) -> Result<()> {
        self.registration.validate()?;
        self.provider.definition().validate()?;
        request.validate_integrity()?;
        if !self.registration.is_active() {
            return Err(AzureEventHubPostureResultError::RegistrationInactive);
        }
        if request.scope_digest != *self.registration.scope_digest()
            || request.expected_provider_digest != self.provider.definition().provider_digest
            || request.expected_registration_digest != *self.registration.registration_digest()
        {
            return Err(AzureEventHubPostureResultError::ScopeMismatch);
        }
        if self.registration.secret_reference().is_revoked() {
            return Err(AzureEventHubPostureResultError::SecretRevoked);
        }
        if self.registration.consent().is_revoked() {
            return Err(AzureEventHubPostureResultError::ConsentRevoked);
        }
        if !self
            .registration
            .consent()
            .is_active_at(request.observed_at)
        {
            return Err(AzureEventHubPostureResultError::ConsentExpired);
        }
        Ok(())
    }
}

pub type AzureEventHubService<T> = AzureEventHubPostureResultService<T>;

fn validate_revision_fence(
    expected: Option<&Digest>,
    observed: &Digest,
) -> std::result::Result<(), AzureEventHubTransportError> {
    observed
        .validate()
        .map_err(|_| AzureEventHubTransportError::InvalidResponse)?;
    if expected.is_some_and(|expected| expected != observed) {
        Err(AzureEventHubTransportError::StaleState)
    } else {
        Ok(())
    }
}

fn posture_state(posture: &AzureEventHubPostureProjection) -> AzureEventHubEvidenceState {
    let statuses = [
        posture.namespace.status,
        posture.namespace.provisioning_state,
        posture.event_hub.status,
        posture.consumer_group.status,
    ];
    if statuses.iter().any(|status| !status.is_known()) {
        AzureEventHubEvidenceState::ProviderUnknown
    } else if statuses
        .iter()
        .any(|status| matches!(status, crate::model::PostureStatus::Disabled))
    {
        AzureEventHubEvidenceState::Disabled
    } else if statuses
        .iter()
        .any(|status| matches!(status, crate::model::PostureStatus::InProgress))
    {
        AzureEventHubEvidenceState::InProgress
    } else {
        AzureEventHubEvidenceState::Ready
    }
}

fn state_for_error(error: &AzureEventHubTransportError) -> AzureEventHubEvidenceState {
    match error {
        AzureEventHubTransportError::ApiDrift => AzureEventHubEvidenceState::ApiDrift,
        AzureEventHubTransportError::ScopeDrift => AzureEventHubEvidenceState::ScopeDrift,
        AzureEventHubTransportError::StaleState => AzureEventHubEvidenceState::StaleState,
        AzureEventHubTransportError::PaginationLoop => AzureEventHubEvidenceState::PaginationLoop,
        AzureEventHubTransportError::Tampered => AzureEventHubEvidenceState::Tampered,
        _ => state_for_transport(error),
    }
}

fn state_for_transport(error: &AzureEventHubTransportError) -> AzureEventHubEvidenceState {
    match error {
        AzureEventHubTransportError::BlockedEnv
        | AzureEventHubTransportError::Unknown
        | AzureEventHubTransportError::InvalidResponse
        | AzureEventHubTransportError::ServerError { .. } => {
            AzureEventHubEvidenceState::ProviderUnknown
        }
        AzureEventHubTransportError::Unauthorized => AzureEventHubEvidenceState::Unauthorized,
        AzureEventHubTransportError::Forbidden => AzureEventHubEvidenceState::Forbidden,
        AzureEventHubTransportError::NotFound => AzureEventHubEvidenceState::NotFound,
        AzureEventHubTransportError::Conflict => AzureEventHubEvidenceState::Conflict,
        AzureEventHubTransportError::RateLimited { .. } => AzureEventHubEvidenceState::Throttled,
        AzureEventHubTransportError::Timeout => AzureEventHubEvidenceState::TimedOut,
        AzureEventHubTransportError::AccessLost => AzureEventHubEvidenceState::AccessLoss,
        AzureEventHubTransportError::Partial => AzureEventHubEvidenceState::Partial,
        AzureEventHubTransportError::Tampered => AzureEventHubEvidenceState::Tampered,
        AzureEventHubTransportError::ApiDrift => AzureEventHubEvidenceState::ApiDrift,
        AzureEventHubTransportError::ScopeDrift => AzureEventHubEvidenceState::ScopeDrift,
        AzureEventHubTransportError::StaleState => AzureEventHubEvidenceState::StaleState,
        AzureEventHubTransportError::PaginationLoop => AzureEventHubEvidenceState::PaginationLoop,
        AzureEventHubTransportError::Revoked => AzureEventHubEvidenceState::RegistrationRevoked,
        AzureEventHubTransportError::BadRequest => AzureEventHubEvidenceState::ProviderUnknown,
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFailure {
    RegistrationInactive,
    RegistrationDigestMismatch,
    ContractDigestMismatch,
    ProviderDigestMismatch,
    ApiDigestMismatch,
    PermissionDigestMismatch,
    ScopeDigestMismatch,
    TamperedEvidence,
    PartialEvidence,
    StaleState,
    AccessLoss,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    Throttled,
    TimedOut,
    ApiDrift,
    ScopeDrift,
    PaginationLoop,
    ProviderUnknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub valid: bool,
    pub review_eligible: bool,
    pub failures: Vec<VerificationFailure>,
    pub verification_digest: Digest,
}

impl VerificationReport {
    fn new(valid: bool, review_eligible: bool, failures: Vec<VerificationFailure>) -> Self {
        let verification_digest = Digest::from_parts(
            "azure-event-hub-verification-report/v1",
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
