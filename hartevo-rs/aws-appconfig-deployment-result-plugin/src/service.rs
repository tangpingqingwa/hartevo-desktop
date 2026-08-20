//! Typed service, proposal, verification, and reversible registration.

use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::consumer::MissionAwsAppConfigConsumer;
use crate::error::{AwsAppConfigDeploymentError, AwsAppConfigTransportError, Result};
use crate::model::{
    AwsAppConfigDeploymentScope, ConsentScope, Cursor, DeploymentFilter, DeploymentMetadata,
    DeploymentProjection, Digest, MissionProjection, PermissionSnapshot, ProjectProjection,
    SecretReference, TransportProvenance, WorkProductProjection, mission_projection,
    project_projection, work_product_projection,
};
use crate::provider::{
    AwsAppConfigOperation, AwsAppConfigProvider, AwsAppConfigProviderDefinition,
    AwsAppConfigTransport, GetDeploymentRequest, GetDeploymentResponse, ListDeploymentsRequest,
    ListDeploymentsResponse,
};
use crate::{
    CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_VERSION, EVIDENCE_LEVEL, MAX_PAGES, PLUGIN_VERSION,
    PROVIDER_ID, SERVICE_ID, contract_digest,
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
            "aws-appconfig-registration-transition/v1",
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
/// registration. The secret handle itself is never retained or serialized.
#[derive(Clone, Eq, PartialEq)]
pub struct AwsAppConfigDeploymentRegistration {
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
    scope: AwsAppConfigDeploymentScope,
    scope_digest: Digest,
    secret_reference: SecretReference,
    registration_revision: u64,
    status: RegistrationStatus,
    registration_digest: Digest,
}

impl AwsAppConfigDeploymentRegistration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        scope: AwsAppConfigDeploymentScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        consent: ConsentScope,
        provider: &AwsAppConfigProviderDefinition,
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
            registration_digest: Digest::from_text("unsealed-aws-appconfig-registration"),
        };
        registration.registration_digest = registration.calculate_digest();
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

    pub fn scope(&self) -> &AwsAppConfigDeploymentScope {
        &self.scope
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn secret_reference(&self) -> &SecretReference {
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
        &self.registration_digest
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
            || self.provider_release.trim().is_empty()
            || self.registration_revision == 0
            || self.scope_digest != self.scope.digest()
            || self.registration_digest != self.calculate_digest()
        {
            return Err(AwsAppConfigDeploymentError::InvalidRegistration);
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
            return Err(AwsAppConfigDeploymentError::InvalidConsent);
        }
        self.consent.validate()
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsAppConfigDeploymentError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Revoked;
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsAppConfigDeploymentError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Reversed;
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsAppConfigDeploymentError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Active;
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-appconfig-registration/v1",
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

impl fmt::Debug for AwsAppConfigDeploymentRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsAppConfigDeploymentRegistration")
            .field("id", &self.id)
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
            .field("registration_digest", &self.registration_digest)
            .finish()
    }
}

impl Serialize for AwsAppConfigDeploymentRegistration {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("AwsAppConfigDeploymentRegistration", 16)?;
        state.serialize_field("id", &self.id)?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("providerRelease", &self.provider_release)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("permissionSnapshot", &self.permission_snapshot)?;
        state.serialize_field("permissionDigest", &self.permission_digest())?;
        state.serialize_field("consentDigest", &self.consent_digest())?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("secretReferenceDigest", &self.secret_reference_digest())?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("registrationDigest", &self.registration_digest)?;
        state.end()
    }
}

pub type AwsAppConfigRegistration = AwsAppConfigDeploymentRegistration;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityDescription {
    pub service_id: String,
    pub plugin_version: String,
    pub contract_version: String,
    pub evidence_level: String,
    pub provider_id: String,
    pub provider_revision: u64,
    pub operations: Vec<String>,
    pub permissions: Vec<String>,
    pub scope_fields: Vec<String>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub kernel_authority: bool,
    pub outcome_adoption: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentEvidenceRequest {
    pub observed_at: DateTime<Utc>,
    pub scope_digest: Digest,
    pub registration_revision: u64,
    pub filter: DeploymentFilter,
    pub request_digest: Digest,
}

impl DeploymentEvidenceRequest {
    pub fn new(
        scope: &AwsAppConfigDeploymentScope,
        registration: &AwsAppConfigDeploymentRegistration,
        observed_at: DateTime<Utc>,
        filter: DeploymentFilter,
    ) -> Result<Self> {
        filter.validate_against(scope)?;
        if registration.scope_digest() != &scope.digest() {
            return Err(AwsAppConfigDeploymentError::ScopeMismatch);
        }
        let request_digest = Digest::from_parts(
            "aws-appconfig-deployment-evidence-request/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                (
                    "registration",
                    registration.registration_digest().as_str().to_owned(),
                ),
                (
                    "registration_revision",
                    registration.registration_revision().to_string(),
                ),
                ("filter", filter.digest().as_str().to_owned()),
                ("observed_at", observed_at.to_rfc3339()),
            ],
        );
        Ok(Self {
            observed_at,
            scope_digest: scope.digest(),
            registration_revision: registration.registration_revision(),
            filter,
            request_digest,
        })
    }

    pub fn validate_against(
        &self,
        scope: &AwsAppConfigDeploymentScope,
        registration: &AwsAppConfigDeploymentRegistration,
    ) -> Result<()> {
        if self.scope_digest != scope.digest()
            || self.registration_revision != registration.registration_revision()
        {
            return Err(AwsAppConfigDeploymentError::ScopeMismatch);
        }
        self.filter.validate_against(scope)?;
        let expected = Self::new(scope, registration, self.observed_at, self.filter.clone())?;
        if self.request_digest != expected.request_digest {
            return Err(AwsAppConfigDeploymentError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentEvidenceState {
    Completed,
    InProgress,
    RollingBack,
    RolledBack,
    Failed,
    Stopped,
    Partial,
    NotFound,
    AccessLoss,
    Throttled,
    ProviderUnknown,
    RegistrationRevoked,
}

impl DeploymentEvidenceState {
    pub const fn is_review_only(self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailureEvidence {
    pub operation: AwsAppConfigOperation,
    pub status_code: Option<u16>,
    pub category: String,
    pub failure_digest: Digest,
}

impl FailureEvidence {
    fn from_transport(
        operation: AwsAppConfigOperation,
        error: &AwsAppConfigTransportError,
    ) -> Self {
        let category = transport_category(error).to_owned();
        let failure_digest = Digest::from_parts(
            "aws-appconfig-failure/v1",
            &[
                ("operation", operation.as_str().to_owned()),
                (
                    "status",
                    error
                        .status_code()
                        .map_or_else(String::new, |status| status.to_string()),
                ),
                ("category", category.clone()),
            ],
        );
        Self {
            operation,
            status_code: error.status_code(),
            category,
            failure_digest,
        }
    }

    fn named(operation: AwsAppConfigOperation, category: &'static str) -> Self {
        Self {
            operation,
            status_code: None,
            category: category.to_owned(),
            failure_digest: Digest::from_parts(
                "aws-appconfig-failure/v1",
                &[
                    ("operation", operation.as_str().to_owned()),
                    ("category", category.to_owned()),
                ],
            ),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub scope_digest: Digest,
    pub filter_digest: Digest,
    pub cursor_digest: Option<Digest>,
    pub list_digest: Option<Digest>,
    pub get_digest: Option<Digest>,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsAppConfigDeploymentProposal {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub registration_digest: Digest,
    pub registration_revision: u64,
    pub scope_digest: Digest,
    pub mission: MissionProjection,
    pub project: ProjectProjection,
    pub work_product: WorkProductProjection,
    pub state: DeploymentEvidenceState,
    pub observed_at: DateTime<Utc>,
    pub list_pages: u16,
    pub list_complete: bool,
    pub evidence: EvidenceDigests,
    pub deployment: Option<DeploymentProjection>,
    pub failure: Option<FailureEvidence>,
    pub provenance: TransportProvenance,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub recoverability_claim: bool,
    pub proposal_digest: Digest,
}

impl Eq for AwsAppConfigDeploymentProposal {}

impl AwsAppConfigDeploymentProposal {
    fn new(
        registration: &AwsAppConfigDeploymentRegistration,
        provider: &AwsAppConfigProviderDefinition,
        request: &DeploymentEvidenceRequest,
        state: DeploymentEvidenceState,
        list_pages: u16,
        list_complete: bool,
        list_digest: Option<Digest>,
        cursor_digest: Option<Digest>,
        get_digest: Option<Digest>,
        deployment: Option<&DeploymentMetadata>,
        failure: Option<FailureEvidence>,
        provenance: TransportProvenance,
    ) -> Self {
        let mut evidence = EvidenceDigests {
            plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_digest: registration.contract_digest.clone(),
            provider_digest: provider.provider_digest.clone(),
            permission_digest: registration.permission_digest(),
            consent_digest: registration.consent_digest(),
            scope_digest: registration.scope_digest().clone(),
            filter_digest: request.filter.digest(),
            cursor_digest,
            list_digest,
            get_digest,
            evidence_digest: Digest::from_text("unsealed-aws-appconfig-evidence"),
        };
        evidence.evidence_digest = calculate_evidence_digest(
            &evidence,
            state,
            list_pages,
            list_complete,
            deployment.map(DeploymentMetadata::projection).as_ref(),
            failure.as_ref(),
        );
        let mut proposal = Self {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            registration_digest: registration.registration_digest().clone(),
            registration_revision: registration.registration_revision(),
            scope_digest: registration.scope_digest().clone(),
            mission: mission_projection(registration.scope().mission()),
            project: project_projection(registration.scope().project()),
            work_product: work_product_projection(registration.scope().work_product()),
            state,
            observed_at: request.observed_at,
            list_pages,
            list_complete,
            evidence,
            deployment: deployment.map(DeploymentMetadata::projection),
            failure,
            provenance,
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            recoverability_claim: false,
            proposal_digest: Digest::from_text("unsealed-aws-appconfig-proposal"),
        };
        proposal.proposal_digest = proposal.calculate_digest();
        proposal
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.service_id != SERVICE_ID
            || self.provider_id != PROVIDER_ID
            || self.consumer_id != CONSUMER_ID
            || self.list_pages > MAX_PAGES
            || !self.review_only
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.recoverability_claim
            || self.provenance.is_native()
            || self.evidence.plugin_version_digest != Digest::from_text(PLUGIN_VERSION)
            || self.evidence.contract_digest.as_str() != CONTRACT_DIGEST
            || self.evidence.evidence_digest
                != calculate_evidence_digest(
                    &self.evidence,
                    self.state,
                    self.list_pages,
                    self.list_complete,
                    self.deployment.as_ref(),
                    self.failure.as_ref(),
                )
            || self.proposal_digest != self.calculate_digest()
        {
            return Err(AwsAppConfigDeploymentError::TamperedEvidence);
        }
        self.evidence.contract_digest.validate()?;
        self.evidence.provider_digest.validate()?;
        self.evidence.permission_digest.validate()?;
        self.evidence.consent_digest.validate()?;
        self.evidence.scope_digest.validate()?;
        self.evidence.filter_digest.validate()?;
        self.evidence
            .cursor_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.evidence
            .list_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        self.evidence
            .get_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()?;
        if let Some(failure) = &self.failure {
            failure.failure_digest.validate()?;
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
            "aws-appconfig-deployment-proposal/v1",
            &[
                ("service", self.service_id.clone()),
                ("provider", self.provider_id.clone()),
                ("consumer", self.consumer_id.clone()),
                ("registration", self.registration_digest.as_str().to_owned()),
                (
                    "registration_revision",
                    self.registration_revision.to_string(),
                ),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("state", format!("{:?}", self.state)),
                ("observed_at", self.observed_at.to_rfc3339()),
                ("list_pages", self.list_pages.to_string()),
                ("list_complete", self.list_complete.to_string()),
                (
                    "evidence",
                    self.evidence.evidence_digest.as_str().to_owned(),
                ),
                (
                    "deployment",
                    self.deployment
                        .as_ref()
                        .map_or_else(String::new, |value| value.digest().as_str().to_owned()),
                ),
                (
                    "failure",
                    self.failure.as_ref().map_or_else(String::new, |value| {
                        value.failure_digest.as_str().to_owned()
                    }),
                ),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFailure {
    InvalidProposal,
    RegistrationInactive,
    ProviderDrift,
    ScopeMismatch,
    NonNativeViolation,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub valid: bool,
    pub review_only: bool,
    pub proposal_digest: Digest,
    pub failures: Vec<VerificationFailure>,
}

impl VerificationReport {
    fn new(
        valid: bool,
        review_only: bool,
        proposal_digest: Digest,
        failures: Vec<VerificationFailure>,
    ) -> Self {
        Self {
            valid,
            review_only,
            proposal_digest,
            failures,
        }
    }
}

/// Layer-1 service for bounded AppConfig deployment metadata.
pub struct AwsAppConfigDeploymentService<T: AwsAppConfigTransport> {
    scope: AwsAppConfigDeploymentScope,
    registration: AwsAppConfigDeploymentRegistration,
    provider: AwsAppConfigProvider<T>,
    now: DateTime<Utc>,
}

impl<T: AwsAppConfigTransport> fmt::Debug for AwsAppConfigDeploymentService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsAppConfigDeploymentService")
            .field("scope_digest", &self.scope.digest())
            .field("registration", &self.registration)
            .field("provider", &self.provider.definition())
            .field("now", &self.now)
            .finish()
    }
}

impl<T: AwsAppConfigTransport> AwsAppConfigDeploymentService<T> {
    pub fn new(
        scope: AwsAppConfigDeploymentScope,
        secret_reference: SecretReference,
        consent: ConsentScope,
        provider: AwsAppConfigProvider<T>,
        now: DateTime<Utc>,
    ) -> Result<Self> {
        let permissions = PermissionSnapshot::for_layer_one(1);
        Self::new_with_permissions(scope, secret_reference, permissions, consent, provider, now)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_permissions(
        scope: AwsAppConfigDeploymentScope,
        secret_reference: SecretReference,
        permissions: PermissionSnapshot,
        consent: ConsentScope,
        provider: AwsAppConfigProvider<T>,
        now: DateTime<Utc>,
    ) -> Result<Self> {
        scope.validate()?;
        provider.definition().validate()?;
        let id = format!("appconfig-registration-{}", &scope.digest().as_str()[..16]);
        let registration = AwsAppConfigDeploymentRegistration::new(
            id,
            scope.clone(),
            secret_reference,
            permissions,
            consent,
            provider.definition(),
            1,
        )?;
        if registration.consent().is_revoked() {
            return Err(AwsAppConfigDeploymentError::ConsentRevoked);
        }
        if !registration.consent().is_active_at(now) {
            return Err(AwsAppConfigDeploymentError::ConsentExpired);
        }
        Ok(Self {
            scope,
            registration,
            provider,
            now,
        })
    }

    pub fn with_registration(
        scope: AwsAppConfigDeploymentScope,
        registration: AwsAppConfigDeploymentRegistration,
        provider: AwsAppConfigProvider<T>,
        now: DateTime<Utc>,
    ) -> Result<Self> {
        scope.validate()?;
        registration.validate()?;
        provider.definition().validate()?;
        if registration.scope_digest() != &scope.digest()
            || registration.provider_digest() != &provider.definition().provider_digest
            || registration.provider_revision() != provider.definition().provider_revision
        {
            return Err(AwsAppConfigDeploymentError::ProviderDrift);
        }
        Ok(Self {
            scope,
            registration,
            provider,
            now,
        })
    }

    pub fn describe_capabilities(&self) -> CapabilityDescription {
        CapabilityDescription {
            service_id: SERVICE_ID.to_owned(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            evidence_level: EVIDENCE_LEVEL.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            provider_revision: self.provider.definition().provider_revision,
            operations: vec!["ListDeployments".to_owned(), "GetDeployment".to_owned()],
            permissions: crate::LAYER1_PERMISSIONS
                .iter()
                .map(|permission| (*permission).to_owned())
                .collect(),
            scope_fields: vec![
                "awsAccountId".to_owned(),
                "awsRegion".to_owned(),
                "applicationId".to_owned(),
                "environmentId".to_owned(),
                "deploymentId".to_owned(),
                "configurationProfileId".to_owned(),
                "configurationVersion".to_owned(),
                "missionId".to_owned(),
                "projectId".to_owned(),
                "workProductId".to_owned(),
            ],
            read_only: true,
            proposal_only: true,
            recording_only: true,
            kernel_authority: false,
            outcome_adoption: false,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        }
    }

    pub fn scope(&self) -> &AwsAppConfigDeploymentScope {
        &self.scope
    }

    pub fn registration(&self) -> &AwsAppConfigDeploymentRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut AwsAppConfigDeploymentRegistration {
        &mut self.registration
    }

    pub fn provider(&self) -> &AwsAppConfigProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsAppConfigProvider<T> {
        &mut self.provider
    }

    pub fn list_deployments(
        &mut self,
        request: &ListDeploymentsRequest,
    ) -> Result<ListDeploymentsResponse> {
        self.registration.validate()?;
        if !self.registration.is_active() {
            return Err(AwsAppConfigDeploymentError::RegistrationInactive);
        }
        if request.scope().digest() != self.scope.digest() {
            return Err(AwsAppConfigDeploymentError::ScopeMismatch);
        }
        Ok(self.provider.list_deployments(request)?)
    }

    pub fn get_deployment(
        &mut self,
        request: &GetDeploymentRequest,
    ) -> Result<GetDeploymentResponse> {
        self.registration.validate()?;
        if !self.registration.is_active() {
            return Err(AwsAppConfigDeploymentError::RegistrationInactive);
        }
        if request.scope().digest() != self.scope.digest() {
            return Err(AwsAppConfigDeploymentError::ScopeMismatch);
        }
        Ok(self.provider.get_deployment(request)?)
    }

    pub fn request(
        &self,
        filter: DeploymentFilter,
        observed_at: DateTime<Utc>,
    ) -> Result<DeploymentEvidenceRequest> {
        DeploymentEvidenceRequest::new(&self.scope, &self.registration, observed_at, filter)
    }

    pub fn default_request(&self, observed_at: DateTime<Utc>) -> Result<DeploymentEvidenceRequest> {
        self.request(DeploymentFilter::for_scope(&self.scope, 20)?, observed_at)
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.revoke()
    }

    pub fn revoke_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.revoke()
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.reverse()
    }

    pub fn reverse_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.reverse()
    }

    pub fn restore_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.restore()
    }

    pub fn consumer(&self) -> Result<MissionAwsAppConfigConsumer> {
        MissionAwsAppConfigConsumer::new(self.scope.clone(), self.registration.clone())
    }

    pub fn verify(&self, proposal: &AwsAppConfigDeploymentProposal) -> VerificationReport {
        let mut failures = Vec::new();
        if proposal.validate_integrity().is_err() {
            failures.push(VerificationFailure::InvalidProposal);
        }
        if !self.registration.is_active() {
            failures.push(VerificationFailure::RegistrationInactive);
        }
        if self.provider.definition().validate().is_err()
            || proposal.evidence.provider_digest != self.provider.definition().provider_digest
        {
            failures.push(VerificationFailure::ProviderDrift);
        }
        if proposal.scope_digest != self.scope.digest()
            || proposal.registration_digest != *self.registration.registration_digest()
        {
            failures.push(VerificationFailure::ScopeMismatch);
        }
        if proposal.connected
            || proposal.native
            || proposal.first_party
            || proposal.provider_receipt
        {
            failures.push(VerificationFailure::NonNativeViolation);
        }
        failures.sort_by_key(|failure| format!("{failure:?}"));
        failures.dedup();
        let valid = failures.is_empty();
        VerificationReport::new(valid, valid, proposal.proposal_digest.clone(), failures)
    }

    pub fn propose(
        &mut self,
        request: DeploymentEvidenceRequest,
    ) -> Result<AwsAppConfigDeploymentProposal> {
        self.registration.validate()?;
        self.provider.definition().validate()?;
        if !self.registration.is_active() {
            return Err(match self.registration.status() {
                RegistrationStatus::Revoked => AwsAppConfigDeploymentError::RegistrationRevoked,
                RegistrationStatus::Reversed => AwsAppConfigDeploymentError::RegistrationReversed,
                RegistrationStatus::Active => AwsAppConfigDeploymentError::RegistrationInactive,
            });
        }
        request.validate_against(&self.scope, &self.registration)?;
        if self.registration.consent().is_revoked() {
            return Err(AwsAppConfigDeploymentError::ConsentRevoked);
        }
        if !self
            .registration
            .consent()
            .is_active_at(request.observed_at)
        {
            return Err(AwsAppConfigDeploymentError::ConsentExpired);
        }

        let mut cursor: Option<Cursor> = None;
        let mut list_pages = 0_u16;
        let mut list_complete = false;
        let mut list_digests = Vec::new();
        let mut target_from_list: Option<DeploymentMetadata> = None;
        let mut final_cursor_digest = None;

        while list_pages < MAX_PAGES {
            let list_request =
                ListDeploymentsRequest::new(&self.scope, request.filter.clone(), cursor.clone())?;
            let response = match self.provider.list_deployments(&list_request) {
                Ok(response) => response,
                Err(error) => {
                    let state = state_from_transport(&error);
                    return Ok(AwsAppConfigDeploymentProposal::new(
                        &self.registration,
                        self.provider.definition(),
                        &request,
                        state,
                        list_pages,
                        false,
                        nonempty_digest(&list_digests),
                        final_cursor_digest,
                        None,
                        None,
                        Some(FailureEvidence::from_transport(
                            AwsAppConfigOperation::ListDeployments,
                            &error,
                        )),
                        self.provider.provenance(),
                    ));
                }
            };
            list_pages = list_pages.saturating_add(1);
            list_digests.push(response.evidence_digest.clone());
            for deployment in &response.deployments {
                if deployment.deployment == self.scope.deployment().clone() {
                    if deployment.validate_against(&self.scope).is_err() {
                        return Ok(self.proposal_with_state(
                            &request,
                            DeploymentEvidenceState::Partial,
                            list_pages,
                            false,
                            nonempty_digest(&list_digests),
                            final_cursor_digest,
                            None,
                            None,
                            Some(FailureEvidence::named(
                                AwsAppConfigOperation::ListDeployments,
                                "deployment_replaced",
                            )),
                        ));
                    }
                    if let Some(previous) = &target_from_list
                        && previous.digest() != deployment.digest()
                    {
                        return Ok(self.proposal_with_state(
                            &request,
                            DeploymentEvidenceState::Partial,
                            list_pages,
                            false,
                            nonempty_digest(&list_digests),
                            final_cursor_digest,
                            None,
                            None,
                            Some(FailureEvidence::named(
                                AwsAppConfigOperation::ListDeployments,
                                "deployment_replaced",
                            )),
                        ));
                    }
                    target_from_list = Some(deployment.clone());
                }
            }
            if let Some(next_cursor) = response.next_cursor {
                final_cursor_digest = Some(next_cursor.token_digest().clone());
                cursor = Some(next_cursor);
            } else {
                list_complete = true;
                break;
            }
        }

        if !list_complete {
            final_cursor_digest = cursor.as_ref().map(|value| value.token_digest().clone());
        }
        let list_digest = nonempty_digest(&list_digests);
        let get_request = GetDeploymentRequest::for_scope(&self.scope)?;
        let get_response = match self.provider.get_deployment(&get_request) {
            Ok(response) => response,
            Err(error) => {
                return Ok(AwsAppConfigDeploymentProposal::new(
                    &self.registration,
                    self.provider.definition(),
                    &request,
                    if !list_complete {
                        DeploymentEvidenceState::Partial
                    } else {
                        state_from_transport(&error)
                    },
                    list_pages,
                    list_complete,
                    list_digest,
                    final_cursor_digest,
                    None,
                    None,
                    Some(FailureEvidence::from_transport(
                        AwsAppConfigOperation::GetDeployment,
                        &error,
                    )),
                    self.provider.provenance(),
                ));
            }
        };
        let get_digest = Some(get_response.evidence_digest.clone());
        let metadata = get_response.deployment.clone();
        if let Some(listed) = &target_from_list {
            if listed.digest() != metadata.digest() {
                return Ok(self.proposal_with_state(
                    &request,
                    DeploymentEvidenceState::Partial,
                    list_pages,
                    list_complete,
                    list_digest,
                    final_cursor_digest,
                    get_digest,
                    Some(&metadata),
                    Some(FailureEvidence::named(
                        AwsAppConfigOperation::GetDeployment,
                        "state_progress_drift",
                    )),
                ));
            }
        } else if list_complete {
            return Ok(self.proposal_with_state(
                &request,
                DeploymentEvidenceState::NotFound,
                list_pages,
                true,
                list_digest,
                final_cursor_digest,
                get_digest,
                Some(&metadata),
                Some(FailureEvidence::named(
                    AwsAppConfigOperation::ListDeployments,
                    "deployment_not_listed",
                )),
            ));
        }
        let state = state_from_metadata(&metadata, request.observed_at, !list_complete);
        Ok(self.proposal_with_state(
            &request,
            state,
            list_pages,
            list_complete,
            list_digest,
            final_cursor_digest,
            get_digest,
            Some(&metadata),
            None,
        ))
    }

    fn proposal_with_state(
        &self,
        request: &DeploymentEvidenceRequest,
        state: DeploymentEvidenceState,
        list_pages: u16,
        list_complete: bool,
        list_digest: Option<Digest>,
        cursor_digest: Option<Digest>,
        get_digest: Option<Digest>,
        deployment: Option<&DeploymentMetadata>,
        failure: Option<FailureEvidence>,
    ) -> AwsAppConfigDeploymentProposal {
        AwsAppConfigDeploymentProposal::new(
            &self.registration,
            self.provider.definition(),
            request,
            state,
            list_pages,
            list_complete,
            list_digest,
            cursor_digest,
            get_digest,
            deployment,
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
            "aws-appconfig-list-pages/v1",
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

fn state_from_transport(error: &AwsAppConfigTransportError) -> DeploymentEvidenceState {
    match error {
        AwsAppConfigTransportError::Unauthorized
        | AwsAppConfigTransportError::Forbidden
        | AwsAppConfigTransportError::AccessLost => DeploymentEvidenceState::AccessLoss,
        AwsAppConfigTransportError::RateLimited { .. } => DeploymentEvidenceState::Throttled,
        AwsAppConfigTransportError::NotFound => DeploymentEvidenceState::NotFound,
        AwsAppConfigTransportError::Partial => DeploymentEvidenceState::Partial,
        AwsAppConfigTransportError::BlockedEnv
        | AwsAppConfigTransportError::BadRequest
        | AwsAppConfigTransportError::Conflict
        | AwsAppConfigTransportError::ServerError { .. }
        | AwsAppConfigTransportError::Timeout
        | AwsAppConfigTransportError::InvalidResponse => DeploymentEvidenceState::ProviderUnknown,
    }
}

fn state_from_metadata(
    metadata: &DeploymentMetadata,
    _observed_at: DateTime<Utc>,
    partial_list: bool,
) -> DeploymentEvidenceState {
    if partial_list || metadata.events_truncated {
        return DeploymentEvidenceState::Partial;
    }
    match metadata.state {
        crate::model::AppConfigDeploymentState::Complete => DeploymentEvidenceState::Completed,
        crate::model::AppConfigDeploymentState::Baking
        | crate::model::AppConfigDeploymentState::Validating
        | crate::model::AppConfigDeploymentState::Deploying => DeploymentEvidenceState::InProgress,
        crate::model::AppConfigDeploymentState::RollingBack => DeploymentEvidenceState::RollingBack,
        crate::model::AppConfigDeploymentState::RolledBack
        | crate::model::AppConfigDeploymentState::Reverted => DeploymentEvidenceState::RolledBack,
        crate::model::AppConfigDeploymentState::DeploymentError
        | crate::model::AppConfigDeploymentState::RollbackError => DeploymentEvidenceState::Failed,
        crate::model::AppConfigDeploymentState::Stopped => DeploymentEvidenceState::Stopped,
    }
}

fn transport_category(error: &AwsAppConfigTransportError) -> &'static str {
    match error {
        AwsAppConfigTransportError::BlockedEnv => "blocked_env",
        AwsAppConfigTransportError::BadRequest => "bad_request",
        AwsAppConfigTransportError::Unauthorized => "unauthorized",
        AwsAppConfigTransportError::Forbidden => "forbidden",
        AwsAppConfigTransportError::NotFound => "not_found",
        AwsAppConfigTransportError::Conflict => "conflict",
        AwsAppConfigTransportError::RateLimited { .. } => "rate_limited",
        AwsAppConfigTransportError::ServerError { .. } => "server_error",
        AwsAppConfigTransportError::Timeout => "timeout",
        AwsAppConfigTransportError::AccessLost => "access_loss",
        AwsAppConfigTransportError::Partial => "partial",
        AwsAppConfigTransportError::InvalidResponse => "invalid_response",
    }
}

fn calculate_evidence_digest(
    evidence: &EvidenceDigests,
    state: DeploymentEvidenceState,
    list_pages: u16,
    list_complete: bool,
    deployment: Option<&DeploymentProjection>,
    failure: Option<&FailureEvidence>,
) -> Digest {
    Digest::from_parts(
        "aws-appconfig-deployment-evidence/v1",
        &[
            (
                "plugin_version",
                evidence.plugin_version_digest.as_str().to_owned(),
            ),
            ("contract", evidence.contract_digest.as_str().to_owned()),
            ("provider", evidence.provider_digest.as_str().to_owned()),
            ("permission", evidence.permission_digest.as_str().to_owned()),
            ("consent", evidence.consent_digest.as_str().to_owned()),
            ("scope", evidence.scope_digest.as_str().to_owned()),
            ("filter", evidence.filter_digest.as_str().to_owned()),
            (
                "cursor",
                evidence
                    .cursor_digest
                    .as_ref()
                    .map_or_else(String::new, |digest| digest.as_str().to_owned()),
            ),
            (
                "list",
                evidence
                    .list_digest
                    .as_ref()
                    .map_or_else(String::new, |digest| digest.as_str().to_owned()),
            ),
            (
                "get",
                evidence
                    .get_digest
                    .as_ref()
                    .map_or_else(String::new, |digest| digest.as_str().to_owned()),
            ),
            ("state", format!("{state:?}")),
            ("list_pages", list_pages.to_string()),
            ("list_complete", list_complete.to_string()),
            (
                "deployment",
                deployment.map_or_else(String::new, |value| value.digest().as_str().to_owned()),
            ),
            (
                "failure",
                failure.map_or_else(String::new, |value| {
                    value.failure_digest.as_str().to_owned()
                }),
            ),
        ],
    )
}
