use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::consumer::MissionHarnessDeliveryConsumer;
use crate::error::{HarnessDeliveryResultError, HarnessTransportError, Result};
use crate::model::{
    ConsentScope, DeploymentMetadata, Digest, ExecutionMetadata, HarnessDeliveryEvidence,
    HarnessDeliveryScope, HarnessEvidenceState, HarnessRunStatus, MissionProjection,
    PaginationEvidence, PermissionSnapshot, PipelineMetadata, ProjectProjection, SecretReference,
    ServiceMetadata, StageMetadata, TransportProvenance, WorkProductProjection,
};
use crate::provider::{
    GetDeploymentRequest, HarnessOperation, HarnessProvider, HarnessProviderDefinition,
    HarnessTransport, ListExecutionsRequest, ListPipelinesRequest, ListServicesRequest,
    ListStagesRequest,
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
            "harness-registration-transition/v1",
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

/// Version/contract/provider/permission/consent/scope/secret-bound
/// registration. The opaque API-key handle itself is never retained.
#[derive(Clone, Eq, PartialEq)]
pub struct HarnessDeliveryRegistration {
    id: String,
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    provider_revision: u64,
    provider_release: String,
    provider_digest: Digest,
    permission_snapshot: PermissionSnapshot,
    consent: ConsentScope,
    scope: HarnessDeliveryScope,
    scope_digest: Digest,
    secret_reference: SecretReference,
    registration_revision: u64,
    status: RegistrationStatus,
    binding_digest: Digest,
}

impl HarnessDeliveryRegistration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        scope: HarnessDeliveryScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        consent: ConsentScope,
        provider: &HarnessProviderDefinition,
        registration_revision: u64,
    ) -> Result<Self> {
        let mut registration = Self {
            id: id.into(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: Digest::parse(CONTRACT_DIGEST.to_owned())?,
            provider_id: provider.provider_id.clone(),
            provider_revision: provider.provider_revision,
            provider_release: provider.release.clone(),
            provider_digest: provider.provider_digest.clone(),
            permission_snapshot,
            consent,
            scope_digest: scope.digest(),
            scope,
            secret_reference,
            registration_revision,
            status: RegistrationStatus::Active,
            binding_digest: Digest::from_text("unsealed-harness-registration"),
        };
        registration.binding_digest = registration.calculate_binding_digest();
        registration.validate()?;
        Ok(registration)
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn plugin_version(&self) -> &str {
        &self.plugin_version
    }

    #[must_use]
    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }

    #[must_use]
    pub fn contract_digest(&self) -> &Digest {
        &self.contract_digest
    }

    #[must_use]
    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    #[must_use]
    pub const fn provider_revision(&self) -> u64 {
        self.provider_revision
    }

    #[must_use]
    pub fn provider_release(&self) -> &str {
        &self.provider_release
    }

    #[must_use]
    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }

    #[must_use]
    pub fn permission_snapshot(&self) -> &PermissionSnapshot {
        &self.permission_snapshot
    }

    #[must_use]
    pub fn permission_digest(&self) -> Digest {
        self.permission_snapshot.digest().clone()
    }

    #[must_use]
    pub fn consent(&self) -> &ConsentScope {
        &self.consent
    }

    #[must_use]
    pub fn consent_digest(&self) -> Digest {
        self.consent.digest().clone()
    }

    #[must_use]
    pub fn scope(&self) -> &HarnessDeliveryScope {
        &self.scope
    }

    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret_reference
    }

    #[must_use]
    pub fn secret_reference_digest(&self) -> &Digest {
        self.secret_reference.reference_digest()
    }

    #[must_use]
    pub const fn registration_revision(&self) -> u64 {
        self.registration_revision
    }

    #[must_use]
    pub const fn status(&self) -> RegistrationStatus {
        self.status
    }

    #[must_use]
    pub fn registration_digest(&self) -> &Digest {
        &self.binding_digest
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.status, RegistrationStatus::Active)
    }

    pub fn validate(&self) -> Result<()> {
        if !valid_id(&self.id)
            || self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest.as_str() != CONTRACT_DIGEST
            || self.contract_digest.as_str() != contract_digest().as_str()
            || self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.provider_release.is_empty()
            || self.registration_revision == 0
            || self.scope_digest != self.scope.digest()
            || self.binding_digest != self.calculate_binding_digest()
        {
            return Err(HarnessDeliveryResultError::InvalidRegistration);
        }
        self.permission_snapshot.validate()?;
        self.scope.validate()?;
        self.secret_reference.validate(&self.scope)?;
        if self
            .permission_snapshot
            .permissions()
            .iter()
            .any(|permission| !self.consent.permissions().contains(permission))
        {
            return Err(HarnessDeliveryResultError::InvalidConsent);
        }
        self.consent.validate()
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(HarnessDeliveryResultError::RegistrationReversed);
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
            return Err(HarnessDeliveryResultError::RegistrationReversed);
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
            return Err(HarnessDeliveryResultError::RegistrationReversed);
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
            "harness-registration/v1",
            &[
                ("id", self.id.clone()),
                ("plugin_version", self.plugin_version.clone()),
                ("contract_version", self.contract_version.clone()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider_id", self.provider_id.clone()),
                ("provider_revision", self.provider_revision.to_string()),
                ("provider_release", self.provider_release.clone()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("permission", self.permission_digest().as_str().to_owned()),
                ("consent", self.consent_digest().as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("secret", self.secret_reference_digest().as_str().to_owned()),
                ("revision", self.registration_revision.to_string()),
                ("status", format!("{:?}", self.status)),
            ],
        )
    }
}

pub type HarnessRegistration = HarnessDeliveryRegistration;

impl fmt::Debug for HarnessDeliveryRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HarnessDeliveryRegistration")
            .field("id", &Digest::from_text(&self.id))
            .field("plugin_version", &self.plugin_version)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider_id", &self.provider_id)
            .field("provider_revision", &self.provider_revision)
            .field("provider_digest", &self.provider_digest)
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

impl Serialize for HarnessDeliveryRegistration {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("HarnessDeliveryRegistration", 16)?;
        state.serialize_field("idDigest", &Digest::from_text(&self.id))?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("providerRelease", &self.provider_release)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("permissionDigest", &self.permission_digest())?;
        state.serialize_field("consentDigest", &self.consent_digest())?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
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
    pub recording_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub outcome_adoption: bool,
    pub work_product_adoption: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackoffHint {
    pub retry_after_seconds: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HarnessDeliveryEvidenceRequest {
    pub scope_digest: Digest,
    pub expected_provider_digest: Digest,
    pub expected_registration_digest: Digest,
    pub max_pages: u16,
    pub observed_at: DateTime<Utc>,
}

impl HarnessDeliveryEvidenceRequest {
    pub fn new(
        scope: &HarnessDeliveryScope,
        expected_provider_digest: Digest,
        expected_registration_digest: Digest,
        max_pages: u16,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        if max_pages == 0 || max_pages > crate::MAX_PAGES {
            return Err(HarnessDeliveryResultError::InvalidRequest);
        }
        expected_provider_digest.validate()?;
        expected_registration_digest.validate()?;
        Ok(Self {
            scope_digest: scope.digest(),
            expected_provider_digest,
            expected_registration_digest,
            max_pages,
            observed_at,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "harness-delivery-evidence-request/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
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
    pub operation: HarnessOperation,
    pub status_code: Option<u16>,
    pub category: String,
    pub failure_digest: Digest,
    pub backoff: Option<BackoffHint>,
}

impl FailureEvidence {
    fn from_transport(operation: HarnessOperation, error: &HarnessTransportError) -> Self {
        let category = match error {
            HarnessTransportError::BlockedEnv => "blocked_env",
            HarnessTransportError::BadRequest => "bad_request",
            HarnessTransportError::Unauthorized => "denied",
            HarnessTransportError::Forbidden => "denied",
            HarnessTransportError::NotFound => "not_found",
            HarnessTransportError::Conflict => "conflict",
            HarnessTransportError::RateLimited { .. } => "rate_limited",
            HarnessTransportError::ServerError { .. } => "provider_unknown",
            HarnessTransportError::Timeout => "provider_unknown",
            HarnessTransportError::AccessLost => "access_loss",
            HarnessTransportError::Partial => "partial",
            HarnessTransportError::InvalidResponse => "invalid_response",
            HarnessTransportError::FixtureMissing => "fixture_missing",
            HarnessTransportError::Unsupported => "unsupported",
        }
        .to_owned();
        let failure_digest = Digest::from_parts(
            "harness-failure/v1",
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
        let backoff = match error {
            HarnessTransportError::RateLimited {
                retry_after_seconds,
            } => Some(BackoffHint {
                retry_after_seconds: *retry_after_seconds,
            }),
            _ => None,
        };
        Self {
            operation,
            status_code: error.status_code(),
            category,
            failure_digest,
            backoff,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HarnessDeliveryProposal {
    pub service_id: String,
    pub consumer_id: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub account_digest: Digest,
    pub org_digest: Digest,
    pub harness_project_digest: Digest,
    pub pipeline_digest: Digest,
    pub execution_digest: Option<Digest>,
    pub mission: MissionProjection,
    pub project: ProjectProjection,
    pub work_product: WorkProductProjection,
    pub state: HarnessEvidenceState,
    pub revision: u64,
    pub evidence: HarnessDeliveryEvidence,
    pub failure: Option<FailureEvidence>,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub proposal_digest: Digest,
}

impl HarnessDeliveryProposal {
    fn new(
        registration: &HarnessDeliveryRegistration,
        request: &HarnessDeliveryEvidenceRequest,
        evidence: HarnessDeliveryEvidence,
        failure: Option<FailureEvidence>,
    ) -> Result<Self> {
        let scope = registration.scope();
        let mut proposal = Self {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            registration_digest: registration.registration_digest().clone(),
            scope_digest: scope.digest(),
            request_digest: request.digest(),
            account_digest: scope.account().digest(),
            org_digest: scope.org().digest(),
            harness_project_digest: scope.harness_project().digest(),
            pipeline_digest: scope.pipeline().digest(),
            execution_digest: evidence
                .execution
                .as_ref()
                .map(|value| value.identifier().digest()),
            mission: scope.mission().clone(),
            project: scope.project().clone(),
            work_product: scope.work_product().clone(),
            state: evidence.state,
            revision: registration.registration_revision(),
            provenance: evidence.provenance,
            evidence,
            failure,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            proposal_digest: Digest::from_text("unsealed-harness-proposal"),
        };
        proposal.proposal_digest = proposal.calculate_digest();
        proposal.validate_integrity()?;
        Ok(proposal)
    }

    #[must_use]
    pub fn evidence_digest(&self) -> &Digest {
        &self.evidence.evidence.evidence_digest
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.service_id != SERVICE_ID
            || self.consumer_id != CONSUMER_ID
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
        {
            return Err(HarnessDeliveryResultError::TamperedEvidence);
        }
        if self.registration_digest.as_str().is_empty()
            || self.request_digest.validate().is_err()
            || self.scope_digest != self.evidence.evidence.scope_digest
            || self.state != self.evidence.state
            || self.provenance != self.evidence.provenance
            || self.proposal_digest != self.calculate_digest()
        {
            return Err(HarnessDeliveryResultError::TamperedEvidence);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "harness-delivery-proposal/v1",
            &[
                ("service", self.service_id.clone()),
                ("consumer", self.consumer_id.clone()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("state", format!("{:?}", self.state)),
                ("revision", self.revision.to_string()),
                (
                    "evidence",
                    self.evidence.evidence.evidence_digest.as_str().to_owned(),
                ),
                (
                    "failure",
                    self.failure.as_ref().map_or_else(String::new, |value| {
                        value.failure_digest.as_str().to_owned()
                    }),
                ),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFailure {
    RegistrationInactive,
    RegistrationDigestMismatch,
    ProviderDigestMismatch,
    PermissionDigestMismatch,
    ConsentDigestMismatch,
    ScopeDigestMismatch,
    TamperedEvidence,
    PartialEvidence,
    Denied,
    RateLimited,
    ProviderUnknown,
    BlockedEnv,
    AccessLoss,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub valid: bool,
    pub review_complete: bool,
    pub failures: Vec<VerificationFailure>,
    pub verification_digest: Digest,
}

impl VerificationReport {
    fn new(valid: bool, review_complete: bool, mut failures: Vec<VerificationFailure>) -> Self {
        failures.sort_unstable();
        failures.dedup();
        let verification_digest = Digest::from_parts(
            "harness-verification/v1",
            &[
                ("valid", valid.to_string()),
                ("review_complete", review_complete.to_string()),
                (
                    "failures",
                    failures
                        .iter()
                        .map(|value| format!("{value:?}"))
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
            ],
        );
        Self {
            valid,
            review_complete,
            failures,
            verification_digest,
        }
    }
}

pub struct HarnessDeliveryResultService<T> {
    registration: HarnessDeliveryRegistration,
    provider: HarnessProvider<T>,
}

impl<T: HarnessTransport> fmt::Debug for HarnessDeliveryResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HarnessDeliveryResultService")
            .field("registration", &self.registration)
            .field("provider", &self.provider)
            .finish()
    }
}

impl<T: HarnessTransport> HarnessDeliveryResultService<T> {
    pub fn new(
        scope: HarnessDeliveryScope,
        secret_reference: SecretReference,
        consent: ConsentScope,
        provider: HarnessProvider<T>,
        _registration_time: DateTime<Utc>,
    ) -> Result<Self> {
        Self::with_registration(
            "harness-delivery-registration",
            scope,
            secret_reference,
            PermissionSnapshot::for_layer_one(1),
            consent,
            provider,
            1,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_registration(
        registration_id: impl Into<String>,
        scope: HarnessDeliveryScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        consent: ConsentScope,
        provider: HarnessProvider<T>,
        registration_revision: u64,
    ) -> Result<Self> {
        let registration = HarnessDeliveryRegistration::new(
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

    #[must_use]
    pub fn describe_capabilities(&self) -> CapabilityDescription {
        CapabilityDescription {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            operations: vec![
                "describe_capabilities",
                "describe_scope",
                "register_scope",
                "read_pipelines",
                "read_executions",
                "read_stages",
                "read_services",
                "read_deployment",
                "compile_delivery_evidence_proposal",
                "verify_delivery_evidence",
                "revoke_registration",
                "reverse_registration",
                "restore_registration",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            permissions: crate::LAYER1_PERMISSIONS
                .iter()
                .map(|permission| (*permission).to_owned())
                .collect(),
            read_only: true,
            proposal_only: true,
            recording_only: true,
            connected: false,
            native: false,
            first_party: false,
            outcome_adoption: false,
            work_product_adoption: false,
        }
    }

    #[must_use]
    pub fn scope(&self) -> &HarnessDeliveryScope {
        self.registration.scope()
    }

    #[must_use]
    pub fn registration(&self) -> &HarnessDeliveryRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut HarnessDeliveryRegistration {
        &mut self.registration
    }

    #[must_use]
    pub fn provider(&self) -> &HarnessProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut HarnessProvider<T> {
        &mut self.provider
    }

    pub fn request(
        &self,
        max_pages: u16,
        observed_at: DateTime<Utc>,
    ) -> Result<HarnessDeliveryEvidenceRequest> {
        HarnessDeliveryEvidenceRequest::new(
            self.scope(),
            self.provider.definition().provider_digest.clone(),
            self.registration.registration_digest().clone(),
            max_pages,
            observed_at,
        )
    }

    pub fn default_request(
        &self,
        observed_at: DateTime<Utc>,
    ) -> Result<HarnessDeliveryEvidenceRequest> {
        self.request(1, observed_at)
    }

    pub fn read_pipelines(
        &mut self,
        request: &ListPipelinesRequest,
    ) -> Result<crate::provider::PipelinePage> {
        let scope = self.scope().clone();
        self.provider.list_pipelines(&scope, request)
    }

    pub fn read_executions(
        &mut self,
        request: &ListExecutionsRequest,
    ) -> Result<crate::provider::ExecutionPage> {
        let scope = self.scope().clone();
        self.provider.list_executions(&scope, request)
    }

    pub fn read_stages(
        &mut self,
        request: &ListStagesRequest,
    ) -> Result<crate::provider::StagePage> {
        let scope = self.scope().clone();
        self.provider.list_stages(&scope, request)
    }

    pub fn read_services(
        &mut self,
        request: &ListServicesRequest,
    ) -> Result<crate::provider::ServicePage> {
        let scope = self.scope().clone();
        self.provider.list_services(&scope, request)
    }

    pub fn read_deployment(
        &mut self,
        request: &GetDeploymentRequest,
    ) -> Result<crate::provider::DeploymentResponse> {
        let scope = self.scope().clone();
        self.provider.get_deployment(&scope, request)
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

    pub fn consumer(&self) -> Result<MissionHarnessDeliveryConsumer> {
        MissionHarnessDeliveryConsumer::new(self.scope().clone(), self.registration.clone())
    }

    pub fn verify(&self, proposal: &HarnessDeliveryProposal) -> VerificationReport {
        let mut failures = Vec::new();
        if !self.registration.is_active() {
            failures.push(VerificationFailure::RegistrationInactive);
        }
        if proposal.registration_digest != *self.registration.registration_digest() {
            failures.push(VerificationFailure::RegistrationDigestMismatch);
        }
        if proposal.evidence.evidence.provider_digest != self.provider.definition().provider_digest
        {
            failures.push(VerificationFailure::ProviderDigestMismatch);
        }
        if proposal.evidence.evidence.permission_digest != self.registration.permission_digest() {
            failures.push(VerificationFailure::PermissionDigestMismatch);
        }
        if proposal.evidence.evidence.consent_digest != self.registration.consent_digest() {
            failures.push(VerificationFailure::ConsentDigestMismatch);
        }
        if proposal.scope_digest != *self.registration.scope_digest() {
            failures.push(VerificationFailure::ScopeDigestMismatch);
        }
        if proposal.validate_integrity().is_err()
            || proposal.evidence.validate_integrity(self.scope()).is_err()
        {
            failures.push(VerificationFailure::TamperedEvidence);
        }
        match proposal.state {
            HarnessEvidenceState::Partial => failures.push(VerificationFailure::PartialEvidence),
            HarnessEvidenceState::Denied => failures.push(VerificationFailure::Denied),
            HarnessEvidenceState::RateLimited => failures.push(VerificationFailure::RateLimited),
            HarnessEvidenceState::ProviderUnknown => {
                failures.push(VerificationFailure::ProviderUnknown);
            }
            HarnessEvidenceState::BlockedEnv => failures.push(VerificationFailure::BlockedEnv),
            HarnessEvidenceState::AccessLoss => failures.push(VerificationFailure::AccessLoss),
            HarnessEvidenceState::Tampered => failures.push(VerificationFailure::TamperedEvidence),
            HarnessEvidenceState::RegistrationRevoked => {
                failures.push(VerificationFailure::RegistrationInactive);
            }
            HarnessEvidenceState::Queued
            | HarnessEvidenceState::Running
            | HarnessEvidenceState::Succeeded
            | HarnessEvidenceState::Failed
            | HarnessEvidenceState::Cancelled => {}
        }
        VerificationReport::new(
            failures.is_empty(),
            failures.is_empty() && proposal.state.is_review_complete(),
            failures,
        )
    }

    pub fn propose(
        &mut self,
        request: HarnessDeliveryEvidenceRequest,
    ) -> Result<HarnessDeliveryProposal> {
        self.registration.validate()?;
        if !self.registration.is_active() {
            return Err(HarnessDeliveryResultError::RegistrationInactive);
        }
        if request.scope_digest != *self.registration.scope_digest()
            || request.expected_provider_digest != self.provider.definition().provider_digest
            || request.expected_registration_digest != *self.registration.registration_digest()
        {
            return Err(HarnessDeliveryResultError::ScopeMismatch);
        }
        if self.registration.consent().is_revoked() {
            return Err(HarnessDeliveryResultError::ConsentRevoked);
        }
        if !self
            .registration
            .consent()
            .is_active_at(request.observed_at)
        {
            return Err(HarnessDeliveryResultError::ConsentExpired);
        }

        let scope = self.scope().clone();
        let pipeline_request = ListPipelinesRequest::for_scope(&scope)?;
        let mut request_digests = vec![pipeline_request.request_digest().clone()];
        let pipeline_page = match self.provider.list_pipelines(&scope, &pipeline_request) {
            Ok(page) => page,
            Err(error) => {
                let error = match error {
                    HarnessDeliveryResultError::Transport(error) => error,
                    other => return Err(other),
                };
                return self.proposal_for_failure(
                    &request,
                    request_digests,
                    HarnessOperation::ListPipelines,
                    error,
                    None,
                    None,
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                );
            }
        };
        let pipeline = pipeline_page
            .pipelines
            .iter()
            .find(|value| value.identifier() == scope.pipeline())
            .cloned();
        let pipeline_cursor = pipeline_page
            .next_cursor
            .as_ref()
            .map(crate::model::OpaqueCursor::digest);
        let mut partial = pipeline_page.next_cursor.is_some();

        let execution_request = ListExecutionsRequest::for_scope(&scope)?;
        request_digests.push(execution_request.request_digest().clone());
        let execution_page = match self.provider.list_executions(&scope, &execution_request) {
            Ok(page) => page,
            Err(error) => {
                let error = match error {
                    HarnessDeliveryResultError::Transport(error) => error,
                    other => return Err(other),
                };
                return self.proposal_for_failure(
                    &request,
                    request_digests,
                    HarnessOperation::ListExecutions,
                    error,
                    pipeline,
                    pipeline_cursor,
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                );
            }
        };
        let execution = if let Some(expected) = scope.execution() {
            execution_page
                .executions
                .iter()
                .find(|value| value.identifier() == expected)
                .cloned()
        } else {
            execution_page.executions.first().cloned()
        };
        if scope.execution().is_some()
            && execution.is_none()
            && execution_page.next_cursor.is_none()
        {
            partial = true;
        }
        partial |= execution_page.next_cursor.is_some();
        let mut stages = Vec::new();
        let mut services = Vec::new();
        let mut deployments = Vec::new();

        if scope.stage().is_some() {
            let stage_request = ListStagesRequest::for_scope(&scope)?;
            request_digests.push(stage_request.request_digest().clone());
            match self.provider.list_stages(&scope, &stage_request) {
                Ok(page) => {
                    stages = page.stages;
                    partial |= page.next_cursor.is_some();
                }
                Err(error) => {
                    let error = match error {
                        HarnessDeliveryResultError::Transport(error) => error,
                        other => return Err(other),
                    };
                    return self.proposal_for_failure(
                        &request,
                        request_digests,
                        HarnessOperation::ListStages,
                        error,
                        pipeline,
                        pipeline_cursor,
                        stages,
                        services,
                        deployments,
                    );
                }
            }
        }

        if scope.service().is_some() {
            let service_request = ListServicesRequest::for_scope(&scope)?;
            request_digests.push(service_request.request_digest().clone());
            match self.provider.list_services(&scope, &service_request) {
                Ok(page) => {
                    services = page.services;
                    partial |= page.next_cursor.is_some();
                }
                Err(error) => {
                    let error = match error {
                        HarnessDeliveryResultError::Transport(error) => error,
                        other => return Err(other),
                    };
                    return self.proposal_for_failure(
                        &request,
                        request_digests,
                        HarnessOperation::ListServices,
                        error,
                        pipeline,
                        pipeline_cursor,
                        stages,
                        services,
                        deployments,
                    );
                }
            }
        }

        let mut deployment_cursor = None;
        if scope.service().is_some() && scope.environment().is_some() {
            let deployment_request = GetDeploymentRequest::for_scope(&scope)?;
            request_digests.push(deployment_request.request_digest().clone());
            match self.provider.get_deployment(&scope, &deployment_request) {
                Ok(response) => {
                    deployment_cursor = Some(response.response_digest.clone());
                    if let Some(deployment) = response.deployment {
                        deployments.push(deployment);
                    }
                }
                Err(error) => {
                    let error = match error {
                        HarnessDeliveryResultError::Transport(error) => error,
                        other => return Err(other),
                    };
                    return self.proposal_for_failure(
                        &request,
                        request_digests,
                        HarnessOperation::GetDeploymentMetadata,
                        error,
                        pipeline,
                        pipeline_cursor,
                        stages,
                        services,
                        deployments,
                    );
                }
            }
        }

        if pipeline.is_none() || execution.is_none() {
            partial = true;
        }
        let state = if partial {
            HarnessEvidenceState::Partial
        } else {
            state_from_metadata(execution.as_ref(), &stages, &services, &deployments)
        };
        let cursor_digest = pipeline_cursor.or(deployment_cursor);
        let pagination = PaginationEvidence::new(request_digests, cursor_digest, 1, !partial)?;
        let evidence = HarnessDeliveryEvidence::new(
            &scope,
            self.provider.definition().provider_digest.clone(),
            self.registration.permission_digest(),
            self.registration.consent_digest(),
            pagination,
            pipeline,
            execution,
            stages,
            services,
            deployments,
            state,
            self.provider.transport_provenance(),
            request.observed_at,
            None,
        )?;
        HarnessDeliveryProposal::new(&self.registration, &request, evidence, None)
    }

    pub fn compile_delivery_evidence_proposal(
        &self,
        request: HarnessDeliveryEvidenceRequest,
        evidence: HarnessDeliveryEvidence,
        failure: Option<FailureEvidence>,
    ) -> Result<HarnessDeliveryProposal> {
        self.registration.validate()?;
        if request.scope_digest != *self.registration.scope_digest()
            || request.expected_provider_digest != self.provider.definition().provider_digest
            || request.expected_registration_digest != *self.registration.registration_digest()
        {
            return Err(HarnessDeliveryResultError::ScopeMismatch);
        }
        HarnessDeliveryProposal::new(&self.registration, &request, evidence, failure)
    }

    fn proposal_for_failure(
        &self,
        request: &HarnessDeliveryEvidenceRequest,
        request_digests: Vec<Digest>,
        operation: HarnessOperation,
        error: HarnessTransportError,
        pipeline: Option<PipelineMetadata>,
        _pipeline_cursor: Option<Digest>,
        stages: Vec<StageMetadata>,
        services: Vec<ServiceMetadata>,
        deployments: Vec<DeploymentMetadata>,
    ) -> Result<HarnessDeliveryProposal> {
        let failure = FailureEvidence::from_transport(operation, &error);
        let state = state_from_transport(&error);
        let pagination = PaginationEvidence::new(request_digests, None, 1, false)?;
        let evidence = HarnessDeliveryEvidence::new(
            self.scope(),
            self.provider.definition().provider_digest.clone(),
            self.registration.permission_digest(),
            self.registration.consent_digest(),
            pagination,
            pipeline,
            None,
            stages,
            services,
            deployments,
            state,
            self.provider.transport_provenance(),
            request.observed_at,
            failure.backoff,
        )?;
        HarnessDeliveryProposal::new(&self.registration, request, evidence, Some(failure))
    }
}

pub type HarnessDeliveryService<T> = HarnessDeliveryResultService<T>;

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= crate::MAX_IDENTIFIER_BYTES
        && value.trim() == value
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn state_from_transport(error: &HarnessTransportError) -> HarnessEvidenceState {
    match error {
        HarnessTransportError::Unauthorized | HarnessTransportError::Forbidden => {
            HarnessEvidenceState::Denied
        }
        HarnessTransportError::RateLimited { .. } => HarnessEvidenceState::RateLimited,
        HarnessTransportError::AccessLost => HarnessEvidenceState::AccessLoss,
        HarnessTransportError::Partial => HarnessEvidenceState::Partial,
        HarnessTransportError::BlockedEnv => HarnessEvidenceState::BlockedEnv,
        HarnessTransportError::BadRequest
        | HarnessTransportError::NotFound
        | HarnessTransportError::Conflict
        | HarnessTransportError::ServerError { .. }
        | HarnessTransportError::Timeout
        | HarnessTransportError::InvalidResponse
        | HarnessTransportError::FixtureMissing
        | HarnessTransportError::Unsupported => HarnessEvidenceState::ProviderUnknown,
    }
}

fn state_from_metadata(
    execution: Option<&ExecutionMetadata>,
    stages: &[StageMetadata],
    services: &[ServiceMetadata],
    deployments: &[DeploymentMetadata],
) -> HarnessEvidenceState {
    let statuses = execution
        .into_iter()
        .map(ExecutionMetadata::status)
        .chain(stages.iter().map(StageMetadata::status))
        .chain(services.iter().map(ServiceMetadata::status))
        .chain(deployments.iter().map(DeploymentMetadata::status))
        .collect::<Vec<_>>();
    if statuses
        .iter()
        .any(|status| matches!(status, HarnessRunStatus::Failed))
    {
        HarnessEvidenceState::Failed
    } else if statuses
        .iter()
        .any(|status| matches!(status, HarnessRunStatus::Cancelled))
    {
        HarnessEvidenceState::Cancelled
    } else if statuses
        .iter()
        .any(|status| matches!(status, HarnessRunStatus::Running))
    {
        HarnessEvidenceState::Running
    } else if statuses
        .iter()
        .any(|status| matches!(status, HarnessRunStatus::Queued))
    {
        HarnessEvidenceState::Queued
    } else if statuses
        .iter()
        .any(|status| matches!(status, HarnessRunStatus::Unknown))
    {
        HarnessEvidenceState::ProviderUnknown
    } else {
        HarnessEvidenceState::Succeeded
    }
}
