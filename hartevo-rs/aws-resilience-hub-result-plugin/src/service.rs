//! Typed service, reversible registration, read/proposal, and verification.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::consumer::MissionAwsResilienceHubConsumer;
use crate::error::{AwsResilienceHubError, AwsResilienceHubTransportError, Result};
use crate::model::{
    ApplicationProjection, AssessmentMetadata, AssessmentProjection, AwsResilienceHubScope,
    ComplianceStatus, ConsentScope, Digest, DriftStatus, EvidenceDigests, PermissionSnapshot,
    SecretReference, TransportProvenance, digest_failure, digest_pages,
};
use crate::provider::{
    AwsResilienceHubOperation, AwsResilienceHubProvider, AwsResilienceHubProviderDefinition,
    DescribeAppAssessmentRequest, DescribeAppRequest, ListAppAssessmentsRequest, ListAppsRequest,
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
            "aws-resilience-hub-registration-transition/v1",
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

/// Version/provider/API/permission/consent/scope/secret/evidence-bound
/// registration. Only the secret digest is retained and serialized.
#[derive(Clone, Eq, PartialEq)]
pub struct AwsResilienceHubRegistration {
    id: String,
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    provider_revision: u64,
    provider_api_revision: String,
    provider_release: String,
    provider_digest: Digest,
    permission_snapshot: PermissionSnapshot,
    consent: ConsentScope,
    scope: AwsResilienceHubScope,
    scope_digest: Digest,
    secret_reference: SecretReference,
    registration_revision: u64,
    status: RegistrationStatus,
    evidence_digest: Digest,
    binding_digest: Digest,
}

impl AwsResilienceHubRegistration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        scope: AwsResilienceHubScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        consent: ConsentScope,
        provider: &AwsResilienceHubProviderDefinition,
        registration_revision: u64,
    ) -> Result<Self> {
        provider.validate()?;
        let mut registration = Self {
            id: id.into(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: Digest::parse(CONTRACT_DIGEST.to_owned())?,
            provider_id: provider.provider_id.clone(),
            provider_revision: provider.provider_revision,
            provider_api_revision: provider.api_revision.clone(),
            provider_release: provider.release.clone(),
            provider_digest: provider.provider_digest.clone(),
            permission_snapshot,
            consent,
            scope_digest: scope.digest(),
            scope,
            secret_reference,
            registration_revision,
            status: RegistrationStatus::Active,
            evidence_digest: Digest::from_text("unsealed-aws-resilience-hub-registration-evidence"),
            binding_digest: Digest::from_text("unsealed-aws-resilience-hub-registration"),
        };
        registration.evidence_digest = registration.calculate_evidence_digest();
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

    pub fn provider_api_revision(&self) -> &str {
        &self.provider_api_revision
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

    pub fn scope(&self) -> &AwsResilienceHubScope {
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
        &self.binding_digest
    }

    pub fn evidence_digest(&self) -> &Digest {
        &self.evidence_digest
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.status, RegistrationStatus::Active)
    }

    pub fn validate(&self) -> Result<()> {
        let expected_provider = AwsResilienceHubProviderDefinition::new(
            self.provider_revision,
            self.provider_release.clone(),
        )?;
        if !valid_id(&self.id)
            || self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest.as_str() != CONTRACT_DIGEST
            || self.contract_digest.as_str() != contract_digest()
            || self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.provider_api_revision != crate::PROVIDER_API_REVISION
            || self.provider_release.is_empty()
            || self.provider_digest != expected_provider.provider_digest
            || self.registration_revision == 0
            || self.scope_digest != self.scope.digest()
            || self.evidence_digest != self.calculate_evidence_digest()
            || self.binding_digest != self.calculate_binding_digest()
        {
            return Err(AwsResilienceHubError::InvalidRegistration);
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
            return Err(AwsResilienceHubError::InvalidConsent);
        }
        self.consent.validate()
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsResilienceHubError::RegistrationReversed);
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
            return Err(AwsResilienceHubError::RegistrationReversed);
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
            return Err(AwsResilienceHubError::RegistrationReversed);
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
            "aws-resilience-hub-registration/v1",
            &[
                ("id", self.id.clone()),
                ("plugin_version", self.plugin_version.clone()),
                ("contract_version", self.contract_version.clone()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider_id", self.provider_id.clone()),
                ("provider_revision", self.provider_revision.to_string()),
                ("provider_api_revision", self.provider_api_revision.clone()),
                ("provider_release", self.provider_release.clone()),
                ("provider", self.provider_digest.as_str().to_owned()),
                (
                    "permission",
                    self.permission_snapshot.digest().as_str().to_owned(),
                ),
                ("consent", self.consent.digest().as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "application_allowlist",
                    self.scope
                        .application_allowlist()
                        .digest()
                        .as_str()
                        .to_owned(),
                ),
                (
                    "assessment_allowlist",
                    self.scope
                        .assessment_allowlist()
                        .digest()
                        .as_str()
                        .to_owned(),
                ),
                (
                    "secret",
                    self.secret_reference.reference_digest().as_str().to_owned(),
                ),
                ("revision", self.registration_revision.to_string()),
                ("status", format!("{:?}", self.status)),
                ("evidence", self.evidence_digest.as_str().to_owned()),
            ],
        )
    }

    fn calculate_evidence_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-resilience-hub-registration-evidence/v1",
            &[
                ("plugin_version", self.plugin_version.clone()),
                ("contract_version", self.contract_version.clone()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider_id", self.provider_id.clone()),
                ("provider_revision", self.provider_revision.to_string()),
                ("provider_api_revision", self.provider_api_revision.clone()),
                ("provider_release", self.provider_release.clone()),
                ("provider", self.provider_digest.as_str().to_owned()),
                (
                    "permission",
                    self.permission_snapshot.digest().as_str().to_owned(),
                ),
                ("consent", self.consent.digest().as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "application_allowlist",
                    self.scope
                        .application_allowlist()
                        .digest()
                        .as_str()
                        .to_owned(),
                ),
                (
                    "assessment_allowlist",
                    self.scope
                        .assessment_allowlist()
                        .digest()
                        .as_str()
                        .to_owned(),
                ),
                (
                    "secret",
                    self.secret_reference.reference_digest().as_str().to_owned(),
                ),
                ("revision", self.registration_revision.to_string()),
            ],
        )
    }
}

impl fmt::Debug for AwsResilienceHubRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsResilienceHubRegistration")
            .field("id_digest", &Digest::from_text(&self.id))
            .field("plugin_version", &self.plugin_version)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider_id", &self.provider_id)
            .field("provider_revision", &self.provider_revision)
            .field("provider_api_revision", &self.provider_api_revision)
            .field("provider_release", &self.provider_release)
            .field("provider_digest", &self.provider_digest)
            .field("permission_digest", &self.permission_digest())
            .field("consent_digest", &self.consent_digest())
            .field("scope_digest", &self.scope_digest)
            .field(
                "application_allowlist_digest",
                &self.scope.application_allowlist().digest(),
            )
            .field(
                "assessment_allowlist_digest",
                &self.scope.assessment_allowlist().digest(),
            )
            .field(
                "secret_reference_digest",
                &self.secret_reference.reference_digest(),
            )
            .field("registration_revision", &self.registration_revision)
            .field("status", &self.status)
            .field("evidence_digest", &self.evidence_digest)
            .field("registration_digest", &self.binding_digest)
            .finish()
    }
}

impl Serialize for AwsResilienceHubRegistration {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("AwsResilienceHubRegistration", 19)?;
        state.serialize_field("idDigest", &Digest::from_text(&self.id))?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("providerApiRevision", &self.provider_api_revision)?;
        state.serialize_field("providerRelease", &self.provider_release)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("permissionDigest", &self.permission_digest())?;
        state.serialize_field("consentDigest", &self.consent_digest())?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field(
            "applicationAllowlistDigest",
            &self.scope.application_allowlist().digest(),
        )?;
        state.serialize_field(
            "assessmentAllowlistDigest",
            &self.scope.assessment_allowlist().digest(),
        )?;
        state.serialize_field(
            "secretReferenceDigest",
            &self.secret_reference.reference_digest(),
        )?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("evidenceDigest", &self.evidence_digest)?;
        state.serialize_field("registrationDigest", &self.binding_digest)?;
        state.end()
    }
}

pub type AwsResilienceHubResultRegistration = AwsResilienceHubRegistration;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityDescription {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub operations: Vec<String>,
    pub permissions: Vec<String>,
    pub read_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub outcome_adoption: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsResilienceHubEvidenceRequest {
    pub scope_digest: Digest,
    pub expected_provider_digest: Digest,
    pub expected_registration_digest: Digest,
    pub max_pages: u16,
    pub observed_at: DateTime<Utc>,
}

impl AwsResilienceHubEvidenceRequest {
    pub fn new(
        scope: &AwsResilienceHubScope,
        provider_digest: Digest,
        registration_digest: Digest,
        max_pages: u16,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        crate::model::bounded_page_count(max_pages)?;
        provider_digest.validate()?;
        registration_digest.validate()?;
        Ok(Self {
            scope_digest: scope.digest(),
            expected_provider_digest: provider_digest,
            expected_registration_digest: registration_digest,
            max_pages,
            observed_at,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResilienceEvidenceState {
    Compliant,
    NonCompliant,
    InProgress,
    Failed,
    Expired,
    Drifted,
    Partial,
    Unknown,
    AccessLoss,
    Throttled,
    NotFound,
    RegistrationRevoked,
}

impl ResilienceEvidenceState {
    pub const fn is_non_adoptable(self) -> bool {
        !matches!(self, Self::Compliant | Self::NonCompliant)
    }

    pub const fn is_review_complete(self) -> bool {
        matches!(self, Self::Compliant | Self::NonCompliant)
    }
}

pub type AssessmentEvidenceState = ResilienceEvidenceState;
pub type AwsResilienceHubAssessmentState = ResilienceEvidenceState;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailureEvidence {
    pub operation: AwsResilienceHubOperation,
    pub status_code: Option<u16>,
    pub category: String,
    pub failure_digest: Digest,
}

impl FailureEvidence {
    fn from_transport(
        operation: AwsResilienceHubOperation,
        error: &AwsResilienceHubTransportError,
    ) -> Self {
        let category = transport_category(error).to_owned();
        let failure_digest = digest_failure(&category, &format!("{error:?}"));
        Self {
            operation,
            status_code: error.status_code(),
            category,
            failure_digest,
        }
    }

    fn local(operation: AwsResilienceHubOperation, category: &str) -> Self {
        Self {
            operation,
            status_code: None,
            category: category.to_owned(),
            failure_digest: digest_failure(category, category),
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFailure {
    RegistrationInactive,
    RegistrationDigestMismatch,
    ProviderDigestMismatch,
    PermissionDigestMismatch,
    ConsentDigestMismatch,
    ScopeDigestMismatch,
    ApplicationAllowlistDigestMismatch,
    AssessmentAllowlistDigestMismatch,
    TamperedEvidence,
    PartialEvidence,
    ExpiredEvidence,
    DriftedEvidence,
    AccessLoss,
    Throttled,
    ProviderUnknown,
    NotFound,
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
            "aws-resilience-hub-verification/v1",
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsResilienceHubProposal {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub evidence: EvidenceDigests,
    pub state: ResilienceEvidenceState,
    pub list_apps_pages: u16,
    pub list_apps_complete: bool,
    pub list_app_assessments_pages: u16,
    pub list_app_assessments_complete: bool,
    pub application: Option<ApplicationProjection>,
    pub assessment: Option<AssessmentProjection>,
    pub failure: Option<FailureEvidence>,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub review_only: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub proposal_digest: Digest,
}

impl AwsResilienceHubProposal {
    #[allow(clippy::too_many_arguments)]
    fn new(
        registration: &AwsResilienceHubRegistration,
        provider: &AwsResilienceHubProviderDefinition,
        request: &AwsResilienceHubEvidenceRequest,
        state: ResilienceEvidenceState,
        list_apps_pages: u16,
        list_apps_complete: bool,
        list_app_assessments_pages: u16,
        list_app_assessments_complete: bool,
        list_apps_digest: Option<Digest>,
        describe_app_digest: Option<Digest>,
        list_app_assessments_digest: Option<Digest>,
        describe_app_assessment_digest: Option<Digest>,
        pagination_digest: Option<Digest>,
        application: Option<ApplicationProjection>,
        assessment: Option<AssessmentProjection>,
        failure: Option<FailureEvidence>,
        provenance: TransportProvenance,
    ) -> Self {
        let mut evidence = EvidenceDigests {
            plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_digest: Digest::parse(CONTRACT_DIGEST.to_owned())
                .expect("contract digest is a checked lowercase SHA-256 digest"),
            provider_digest: provider.provider_digest.clone(),
            permission_digest: registration.permission_digest(),
            consent_digest: registration.consent_digest(),
            scope_digest: request.scope_digest.clone(),
            application_allowlist_digest: registration.scope.application_allowlist().digest(),
            assessment_allowlist_digest: registration.scope.assessment_allowlist().digest(),
            list_apps_digest,
            describe_app_digest,
            list_app_assessments_digest,
            describe_app_assessment_digest,
            pagination_digest,
            evidence_digest: Digest::from_text("unsealed-aws-resilience-hub-evidence"),
        };
        evidence.evidence_digest = calculate_evidence_digest(
            &evidence,
            state,
            list_apps_pages,
            list_apps_complete,
            list_app_assessments_pages,
            list_app_assessments_complete,
            application.as_ref(),
            assessment.as_ref(),
            failure.as_ref(),
        );
        let mut proposal = Self {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            registration_digest: registration.registration_digest().clone(),
            scope_digest: request.scope_digest.clone(),
            evidence,
            state,
            list_apps_pages,
            list_apps_complete,
            list_app_assessments_pages,
            list_app_assessments_complete,
            application,
            assessment,
            failure,
            provenance,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            review_only: true,
            outcome_adopted: false,
            work_product_adopted: false,
            proposal_digest: Digest::from_text("unsealed-aws-resilience-hub-proposal"),
        };
        proposal.proposal_digest = proposal.calculate_digest();
        proposal
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub const fn is_review_only(&self) -> bool {
        self.review_only
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.service_id != SERVICE_ID
            || self.provider_id != PROVIDER_ID
            || self.consumer_id != CONSUMER_ID
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || !self.review_only
            || self.outcome_adopted
            || self.work_product_adopted
            || self.list_apps_complete && self.list_apps_pages == 0
            || self.list_app_assessments_complete && self.list_app_assessments_pages == 0
            || self.evidence.validate().is_err()
            || self.evidence.plugin_version_digest != Digest::from_text(PLUGIN_VERSION)
            || self.evidence.contract_digest
                != Digest::parse(CONTRACT_DIGEST.to_owned())
                    .expect("contract digest is a checked lowercase SHA-256 digest")
            || self.evidence.scope_digest != self.scope_digest
            || self.evidence.evidence_digest
                != calculate_evidence_digest(
                    &self.evidence,
                    self.state,
                    self.list_apps_pages,
                    self.list_apps_complete,
                    self.list_app_assessments_pages,
                    self.list_app_assessments_complete,
                    self.application.as_ref(),
                    self.assessment.as_ref(),
                    self.failure.as_ref(),
                )
            || self.proposal_digest != self.calculate_digest()
        {
            return Err(AwsResilienceHubError::TamperedEvidence);
        }
        if self.state.is_non_adoptable() && self.proposal_digest == Digest::from_text("adopted") {
            return Err(AwsResilienceHubError::TamperedEvidence);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-resilience-hub-proposal/v1",
            &[
                ("service", self.service_id.clone()),
                ("provider", self.provider_id.clone()),
                ("consumer", self.consumer_id.clone()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "evidence",
                    serde_json::to_string(&self.evidence).expect("evidence serializes"),
                ),
                ("state", format!("{:?}", self.state)),
                ("list_apps_pages", self.list_apps_pages.to_string()),
                ("list_apps_complete", self.list_apps_complete.to_string()),
                (
                    "list_app_assessments_pages",
                    self.list_app_assessments_pages.to_string(),
                ),
                (
                    "list_app_assessments_complete",
                    self.list_app_assessments_complete.to_string(),
                ),
                (
                    "application",
                    self.application.as_ref().map_or_else(String::new, |value| {
                        value.evidence_digest().as_str().to_owned()
                    }),
                ),
                (
                    "assessment",
                    self.assessment.as_ref().map_or_else(String::new, |value| {
                        value.evidence_digest().as_str().to_owned()
                    }),
                ),
                (
                    "failure",
                    self.failure.as_ref().map_or_else(String::new, |value| {
                        serde_json::to_string(value).expect("failure serializes")
                    }),
                ),
                ("provenance", self.provenance.as_str().to_owned()),
                ("review_only", self.review_only.to_string()),
            ],
        )
    }
}

pub type AwsResilienceHubRead = AwsResilienceHubProposal;
pub type AwsResilienceHubResult = AwsResilienceHubProposal;

pub struct AwsResilienceHubService<T> {
    registration: AwsResilienceHubRegistration,
    provider: AwsResilienceHubProvider<T>,
}

impl<T: crate::provider::AwsResilienceHubTransport> fmt::Debug for AwsResilienceHubService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsResilienceHubService")
            .field("registration", &self.registration)
            .field("provider", &self.provider)
            .finish()
    }
}

impl<T: crate::provider::AwsResilienceHubTransport> AwsResilienceHubService<T> {
    pub fn new(
        scope: AwsResilienceHubScope,
        secret_reference: SecretReference,
        consent: ConsentScope,
        provider: AwsResilienceHubProvider<T>,
        registration_time: DateTime<Utc>,
    ) -> Result<Self> {
        Self::with_registration(
            "aws-resilience-hub-registration",
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
        scope: AwsResilienceHubScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        consent: ConsentScope,
        provider: AwsResilienceHubProvider<T>,
        registration_revision: u64,
        _registration_time: DateTime<Utc>,
    ) -> Result<Self> {
        let registration = AwsResilienceHubRegistration::new(
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
            operations: [
                AwsResilienceHubOperation::ListApps,
                AwsResilienceHubOperation::DescribeApp,
                AwsResilienceHubOperation::ListAppAssessments,
                AwsResilienceHubOperation::DescribeAppAssessment,
            ]
            .into_iter()
            .map(|operation| operation.as_str().to_owned())
            .collect(),
            permissions: crate::LAYER1_PERMISSIONS
                .iter()
                .map(|permission| (*permission).to_owned())
                .collect(),
            read_only: true,
            connected: false,
            native: false,
            first_party: false,
            outcome_adoption: false,
        }
    }

    pub fn scope(&self) -> &AwsResilienceHubScope {
        self.registration.scope()
    }

    pub fn registration(&self) -> &AwsResilienceHubRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut AwsResilienceHubRegistration {
        &mut self.registration
    }

    pub fn provider(&self) -> &AwsResilienceHubProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsResilienceHubProvider<T> {
        &mut self.provider
    }

    pub fn request(
        &self,
        max_pages: u16,
        observed_at: DateTime<Utc>,
    ) -> Result<AwsResilienceHubEvidenceRequest> {
        AwsResilienceHubEvidenceRequest::new(
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
    ) -> Result<AwsResilienceHubEvidenceRequest> {
        self.request(1, observed_at)
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

    pub fn consumer(&self) -> Result<MissionAwsResilienceHubConsumer> {
        MissionAwsResilienceHubConsumer::new(self.scope().clone(), self.registration.clone())
    }

    pub fn read(
        &mut self,
        request: AwsResilienceHubEvidenceRequest,
    ) -> Result<AwsResilienceHubRead> {
        self.propose(request)
    }

    pub fn propose(
        &mut self,
        request: AwsResilienceHubEvidenceRequest,
    ) -> Result<AwsResilienceHubProposal> {
        self.registration.validate()?;
        if !self.registration.is_active() {
            return Err(AwsResilienceHubError::RegistrationInactive);
        }
        if request.scope_digest != *self.registration.scope_digest()
            || request.expected_provider_digest != self.provider.definition().provider_digest
            || request.expected_registration_digest != *self.registration.registration_digest()
        {
            return Err(AwsResilienceHubError::ScopeMismatch);
        }
        if self.registration.consent().is_revoked() {
            return Err(AwsResilienceHubError::ConsentRevoked);
        }
        if !self
            .registration
            .consent()
            .is_active_at(request.observed_at)
        {
            return Err(AwsResilienceHubError::ConsentExpired);
        }

        let mut list_apps_cursor = None;
        let mut list_apps_pages = 0_u16;
        let mut list_apps_complete = false;
        let mut list_apps_digests = Vec::new();
        let mut listed_application: Option<ApplicationProjection> = None;
        let mut seen_app_cursors = BTreeSet::new();
        loop {
            if list_apps_pages >= request.max_pages {
                break;
            }
            let list_request =
                ListAppsRequest::new(self.scope(), crate::MAX_PAGE_SIZE, list_apps_cursor.clone())?;
            let response = match self.provider.list_apps(&list_request) {
                Ok(response) => response,
                Err(error) => {
                    return Ok(self.proposal_for_failure(
                        &request,
                        failure_state(&error, list_apps_pages > 0),
                        list_apps_pages,
                        false,
                        0,
                        false,
                        digest_pages(&list_apps_digests),
                        None,
                        None,
                        None,
                        None,
                        None,
                        Some(FailureEvidence::from_transport(
                            AwsResilienceHubOperation::ListApps,
                            &error,
                        )),
                    ));
                }
            };
            list_apps_pages = list_apps_pages.saturating_add(1);
            list_apps_digests.push(response.evidence_digest.clone());
            for application in &response.applications {
                if application.application_digest() == &self.scope().application().digest() {
                    if let Some(previous) = &listed_application {
                        if previous.evidence_digest() != application.evidence_digest() {
                            return Ok(self.proposal_for_failure(
                                &request,
                                ResilienceEvidenceState::Drifted,
                                list_apps_pages,
                                false,
                                0,
                                false,
                                digest_pages(&list_apps_digests),
                                None,
                                None,
                                None,
                                None,
                                None,
                                Some(FailureEvidence::local(
                                    AwsResilienceHubOperation::ListApps,
                                    "application_replaced",
                                )),
                            ));
                        }
                    }
                    listed_application = Some(application.clone());
                }
            }
            if let Some(cursor) = response.next_cursor.clone() {
                if !seen_app_cursors.insert(cursor.token_digest().clone()) {
                    return Ok(self.proposal_for_failure(
                        &request,
                        ResilienceEvidenceState::Partial,
                        list_apps_pages,
                        false,
                        0,
                        false,
                        digest_pages(&list_apps_digests),
                        None,
                        None,
                        None,
                        None,
                        None,
                        Some(FailureEvidence::local(
                            AwsResilienceHubOperation::ListApps,
                            "pagination_loop",
                        )),
                    ));
                }
                list_apps_cursor = Some(cursor);
            } else {
                list_apps_complete = true;
                break;
            }
        }
        let list_apps_digest = digest_pages(&list_apps_digests);
        if !list_apps_complete {
            return Ok(self.proposal_for_failure(
                &request,
                ResilienceEvidenceState::Partial,
                list_apps_pages,
                false,
                0,
                false,
                list_apps_digest,
                None,
                None,
                None,
                None,
                None,
                Some(FailureEvidence::local(
                    AwsResilienceHubOperation::ListApps,
                    "page_bound",
                )),
            ));
        }
        if listed_application.is_none() {
            return Ok(self.proposal_for_failure(
                &request,
                ResilienceEvidenceState::NotFound,
                list_apps_pages,
                true,
                0,
                false,
                list_apps_digest,
                None,
                None,
                None,
                None,
                None,
                Some(FailureEvidence::local(
                    AwsResilienceHubOperation::ListApps,
                    "application_not_found",
                )),
            ));
        }

        let describe_app_request = DescribeAppRequest::for_scope(self.scope())?;
        let describe_app_response = match self.provider.describe_app(&describe_app_request) {
            Ok(response) => response,
            Err(error) => {
                return Ok(self.proposal_for_failure(
                    &request,
                    failure_state(&error, false),
                    list_apps_pages,
                    true,
                    0,
                    false,
                    list_apps_digest,
                    None,
                    None,
                    None,
                    None,
                    None,
                    Some(FailureEvidence::from_transport(
                        AwsResilienceHubOperation::DescribeApp,
                        &error,
                    )),
                ));
            }
        };
        if listed_application.as_ref().is_some_and(|application| {
            application.evidence_digest() != describe_app_response.application.evidence_digest()
        }) {
            return Ok(self.proposal_for_failure(
                &request,
                ResilienceEvidenceState::Drifted,
                list_apps_pages,
                true,
                0,
                false,
                list_apps_digest,
                Some(describe_app_response.evidence_digest.clone()),
                None,
                None,
                Some(describe_app_response.application.clone()),
                None,
                Some(FailureEvidence::local(
                    AwsResilienceHubOperation::DescribeApp,
                    "application_drift",
                )),
            ));
        }

        let mut list_assessments_cursor = None;
        let mut list_assessments_pages = 0_u16;
        let mut list_assessments_complete = false;
        let mut list_assessments_digests = Vec::new();
        let mut listed_assessment: Option<AssessmentMetadata> = None;
        let mut seen_assessment_cursors = BTreeSet::new();
        loop {
            if list_assessments_pages >= request.max_pages {
                break;
            }
            let list_request = ListAppAssessmentsRequest::new(
                self.scope(),
                crate::MAX_PAGE_SIZE,
                list_assessments_cursor.clone(),
            )?;
            let response = match self.provider.list_app_assessments(&list_request) {
                Ok(response) => response,
                Err(error) => {
                    return Ok(self.proposal_for_failure(
                        &request,
                        failure_state(&error, list_assessments_pages > 0),
                        list_apps_pages,
                        true,
                        list_assessments_pages,
                        false,
                        list_apps_digest,
                        Some(describe_app_response.evidence_digest.clone()),
                        digest_pages(&list_assessments_digests),
                        None,
                        Some(describe_app_response.application.clone()),
                        None,
                        Some(FailureEvidence::from_transport(
                            AwsResilienceHubOperation::ListAppAssessments,
                            &error,
                        )),
                    ));
                }
            };
            list_assessments_pages = list_assessments_pages.saturating_add(1);
            list_assessments_digests.push(response.evidence_digest.clone());
            for assessment in &response.assessments {
                if assessment.assessment_digest() == &self.scope().assessment().digest() {
                    if let Some(previous) = &listed_assessment {
                        if previous.evidence_digest() != assessment.evidence_digest() {
                            return Ok(self.proposal_for_failure(
                                &request,
                                ResilienceEvidenceState::Drifted,
                                list_apps_pages,
                                true,
                                list_assessments_pages,
                                false,
                                list_apps_digest.clone(),
                                Some(describe_app_response.evidence_digest.clone()),
                                digest_pages(&list_assessments_digests),
                                None,
                                Some(describe_app_response.application.clone()),
                                None,
                                Some(FailureEvidence::local(
                                    AwsResilienceHubOperation::ListAppAssessments,
                                    "assessment_replaced",
                                )),
                            ));
                        }
                    }
                    listed_assessment = Some(assessment.clone());
                }
            }
            if let Some(cursor) = response.next_cursor.clone() {
                if !seen_assessment_cursors.insert(cursor.token_digest().clone()) {
                    return Ok(self.proposal_for_failure(
                        &request,
                        ResilienceEvidenceState::Partial,
                        list_apps_pages,
                        true,
                        list_assessments_pages,
                        false,
                        list_apps_digest.clone(),
                        Some(describe_app_response.evidence_digest.clone()),
                        digest_pages(&list_assessments_digests),
                        None,
                        Some(describe_app_response.application.clone()),
                        None,
                        Some(FailureEvidence::local(
                            AwsResilienceHubOperation::ListAppAssessments,
                            "pagination_loop",
                        )),
                    ));
                }
                list_assessments_cursor = Some(cursor);
            } else {
                list_assessments_complete = true;
                break;
            }
        }
        let list_assessments_digest = digest_pages(&list_assessments_digests);
        if !list_assessments_complete {
            return Ok(self.proposal_for_failure(
                &request,
                ResilienceEvidenceState::Partial,
                list_apps_pages,
                true,
                list_assessments_pages,
                false,
                list_apps_digest,
                Some(describe_app_response.evidence_digest.clone()),
                list_assessments_digest,
                None,
                Some(describe_app_response.application.clone()),
                None,
                Some(FailureEvidence::local(
                    AwsResilienceHubOperation::ListAppAssessments,
                    "page_bound",
                )),
            ));
        }
        if listed_assessment.is_none() {
            return Ok(self.proposal_for_failure(
                &request,
                ResilienceEvidenceState::NotFound,
                list_apps_pages,
                true,
                list_assessments_pages,
                true,
                list_apps_digest,
                Some(describe_app_response.evidence_digest.clone()),
                list_assessments_digest,
                None,
                Some(describe_app_response.application.clone()),
                None,
                Some(FailureEvidence::local(
                    AwsResilienceHubOperation::ListAppAssessments,
                    "assessment_not_found",
                )),
            ));
        }

        let describe_assessment_request = DescribeAppAssessmentRequest::for_scope(self.scope())?;
        let describe_assessment_response = match self
            .provider
            .describe_app_assessment(&describe_assessment_request)
        {
            Ok(response) => response,
            Err(error) => {
                return Ok(self.proposal_for_failure(
                    &request,
                    failure_state(&error, false),
                    list_apps_pages,
                    true,
                    list_assessments_pages,
                    true,
                    list_apps_digest,
                    Some(describe_app_response.evidence_digest.clone()),
                    list_assessments_digest,
                    None,
                    Some(describe_app_response.application.clone()),
                    None,
                    Some(FailureEvidence::from_transport(
                        AwsResilienceHubOperation::DescribeAppAssessment,
                        &error,
                    )),
                ));
            }
        };
        if listed_assessment.as_ref().is_some_and(|assessment| {
            assessment.evidence_digest()
                != describe_assessment_response.assessment.evidence_digest()
        }) {
            return Ok(self.proposal_for_failure(
                &request,
                ResilienceEvidenceState::Drifted,
                list_apps_pages,
                true,
                list_assessments_pages,
                true,
                list_apps_digest,
                Some(describe_app_response.evidence_digest.clone()),
                list_assessments_digest,
                Some(describe_assessment_response.evidence_digest.clone()),
                Some(describe_app_response.application.clone()),
                Some(describe_assessment_response.assessment.clone()),
                Some(FailureEvidence::local(
                    AwsResilienceHubOperation::DescribeAppAssessment,
                    "assessment_drift",
                )),
            ));
        }

        let assessment = describe_assessment_response.assessment.clone();
        let state = state_from_metadata(
            &assessment,
            &describe_app_response.application,
            request.observed_at,
        );
        Ok(self.proposal_for_failure(
            &request,
            state,
            list_apps_pages,
            true,
            list_assessments_pages,
            true,
            list_apps_digest,
            Some(describe_app_response.evidence_digest),
            list_assessments_digest,
            Some(describe_assessment_response.evidence_digest),
            Some(describe_app_response.application),
            Some(assessment),
            None,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn proposal_for_failure(
        &self,
        request: &AwsResilienceHubEvidenceRequest,
        state: ResilienceEvidenceState,
        list_apps_pages: u16,
        list_apps_complete: bool,
        list_app_assessments_pages: u16,
        list_app_assessments_complete: bool,
        list_apps_digest: Option<Digest>,
        describe_app_digest: Option<Digest>,
        list_app_assessments_digest: Option<Digest>,
        describe_app_assessment_digest: Option<Digest>,
        application: Option<ApplicationProjection>,
        assessment: Option<AssessmentProjection>,
        failure: Option<FailureEvidence>,
    ) -> AwsResilienceHubProposal {
        let pagination_digest = Digest::from_parts(
            "aws-resilience-hub-pagination/v1",
            &[
                ("list_apps_pages", list_apps_pages.to_string()),
                ("list_apps_complete", list_apps_complete.to_string()),
                (
                    "list_assessments_pages",
                    list_app_assessments_pages.to_string(),
                ),
                (
                    "list_assessments_complete",
                    list_app_assessments_complete.to_string(),
                ),
            ],
        );
        AwsResilienceHubProposal::new(
            &self.registration,
            self.provider.definition(),
            request,
            state,
            list_apps_pages,
            list_apps_complete,
            list_app_assessments_pages,
            list_app_assessments_complete,
            list_apps_digest,
            describe_app_digest,
            list_app_assessments_digest,
            describe_app_assessment_digest,
            Some(pagination_digest),
            application,
            assessment,
            failure,
            self.provider.provenance(),
        )
    }

    pub fn verify(&self, proposal: &AwsResilienceHubProposal) -> VerificationReport {
        let mut failures = Vec::new();
        if !self.registration.is_active() {
            failures.push(VerificationFailure::RegistrationInactive);
        }
        if proposal.registration_digest != *self.registration.registration_digest() {
            failures.push(VerificationFailure::RegistrationDigestMismatch);
        }
        if proposal.evidence.provider_digest != self.provider.definition().provider_digest {
            failures.push(VerificationFailure::ProviderDigestMismatch);
        }
        if proposal.evidence.permission_digest != self.registration.permission_digest() {
            failures.push(VerificationFailure::PermissionDigestMismatch);
        }
        if proposal.evidence.consent_digest != self.registration.consent_digest() {
            failures.push(VerificationFailure::ConsentDigestMismatch);
        }
        if proposal.scope_digest != *self.registration.scope_digest() {
            failures.push(VerificationFailure::ScopeDigestMismatch);
        }
        if proposal.evidence.application_allowlist_digest
            != self.scope().application_allowlist().digest()
        {
            failures.push(VerificationFailure::ApplicationAllowlistDigestMismatch);
        }
        if proposal.evidence.assessment_allowlist_digest
            != self.scope().assessment_allowlist().digest()
        {
            failures.push(VerificationFailure::AssessmentAllowlistDigestMismatch);
        }
        if proposal.validate_integrity().is_err() {
            failures.push(VerificationFailure::TamperedEvidence);
        }
        match proposal.state {
            ResilienceEvidenceState::Partial => failures.push(VerificationFailure::PartialEvidence),
            ResilienceEvidenceState::Expired => failures.push(VerificationFailure::ExpiredEvidence),
            ResilienceEvidenceState::Drifted => failures.push(VerificationFailure::DriftedEvidence),
            ResilienceEvidenceState::AccessLoss => failures.push(VerificationFailure::AccessLoss),
            ResilienceEvidenceState::Throttled => failures.push(VerificationFailure::Throttled),
            ResilienceEvidenceState::Unknown | ResilienceEvidenceState::Failed => {
                failures.push(VerificationFailure::ProviderUnknown);
            }
            ResilienceEvidenceState::NotFound => failures.push(VerificationFailure::NotFound),
            ResilienceEvidenceState::RegistrationRevoked => {
                failures.push(VerificationFailure::RegistrationInactive);
            }
            ResilienceEvidenceState::Compliant
            | ResilienceEvidenceState::NonCompliant
            | ResilienceEvidenceState::InProgress => {}
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

    pub fn record(
        &self,
        proposal: &AwsResilienceHubProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<crate::consumer::RecordedAwsResilienceHubResult> {
        let mut consumer = self.consumer()?;
        consumer.record(proposal, idempotency_key)
    }
}

#[allow(clippy::too_many_arguments)]
fn calculate_evidence_digest(
    evidence: &EvidenceDigests,
    state: ResilienceEvidenceState,
    list_apps_pages: u16,
    list_apps_complete: bool,
    list_app_assessments_pages: u16,
    list_app_assessments_complete: bool,
    application: Option<&ApplicationProjection>,
    assessment: Option<&AssessmentProjection>,
    failure: Option<&FailureEvidence>,
) -> Digest {
    Digest::from_parts(
        "aws-resilience-hub-evidence/v1",
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
            (
                "application_allowlist",
                evidence.application_allowlist_digest.as_str().to_owned(),
            ),
            (
                "assessment_allowlist",
                evidence.assessment_allowlist_digest.as_str().to_owned(),
            ),
            (
                "list_apps",
                evidence
                    .list_apps_digest
                    .as_ref()
                    .map_or_else(String::new, |digest| digest.as_str().to_owned()),
            ),
            (
                "describe_app",
                evidence
                    .describe_app_digest
                    .as_ref()
                    .map_or_else(String::new, |digest| digest.as_str().to_owned()),
            ),
            (
                "list_app_assessments",
                evidence
                    .list_app_assessments_digest
                    .as_ref()
                    .map_or_else(String::new, |digest| digest.as_str().to_owned()),
            ),
            (
                "describe_app_assessment",
                evidence
                    .describe_app_assessment_digest
                    .as_ref()
                    .map_or_else(String::new, |digest| digest.as_str().to_owned()),
            ),
            (
                "pagination",
                evidence
                    .pagination_digest
                    .as_ref()
                    .map_or_else(String::new, |digest| digest.as_str().to_owned()),
            ),
            ("state", format!("{state:?}")),
            ("list_apps_pages", list_apps_pages.to_string()),
            ("list_apps_complete", list_apps_complete.to_string()),
            (
                "list_app_assessments_pages",
                list_app_assessments_pages.to_string(),
            ),
            (
                "list_app_assessments_complete",
                list_app_assessments_complete.to_string(),
            ),
            (
                "application",
                application.map_or_else(String::new, |value| {
                    value.evidence_digest().as_str().to_owned()
                }),
            ),
            (
                "assessment",
                assessment.map_or_else(String::new, |value| {
                    value.evidence_digest().as_str().to_owned()
                }),
            ),
            (
                "failure",
                failure.map_or_else(String::new, |value| {
                    serde_json::to_string(value).expect("failure serializes")
                }),
            ),
        ],
    )
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= crate::MAX_IDENTIFIER_BYTES
        && value.trim() == value
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn transport_category(error: &AwsResilienceHubTransportError) -> &'static str {
    match error {
        AwsResilienceHubTransportError::BlockedEnv => "blocked_env",
        AwsResilienceHubTransportError::BadRequest => "bad_request",
        AwsResilienceHubTransportError::Unauthorized => "unauthorized",
        AwsResilienceHubTransportError::Forbidden => "forbidden",
        AwsResilienceHubTransportError::NotFound => "not_found",
        AwsResilienceHubTransportError::RateLimited { .. } => "throttled",
        AwsResilienceHubTransportError::ServerError { .. } => "server_error",
        AwsResilienceHubTransportError::Timeout => "timeout",
        AwsResilienceHubTransportError::AccessLost => "access_loss",
        AwsResilienceHubTransportError::Partial => "partial",
        AwsResilienceHubTransportError::PaginationLoop => "pagination_loop",
        AwsResilienceHubTransportError::InvalidResponse => "invalid_response",
        AwsResilienceHubTransportError::Drift => "drift",
    }
}

fn failure_state(
    error: &AwsResilienceHubTransportError,
    had_pages: bool,
) -> ResilienceEvidenceState {
    if had_pages
        || matches!(
            error,
            AwsResilienceHubTransportError::Partial
                | AwsResilienceHubTransportError::PaginationLoop
        )
    {
        return ResilienceEvidenceState::Partial;
    }
    match error {
        AwsResilienceHubTransportError::Unauthorized
        | AwsResilienceHubTransportError::Forbidden
        | AwsResilienceHubTransportError::AccessLost => ResilienceEvidenceState::AccessLoss,
        AwsResilienceHubTransportError::RateLimited { .. } => ResilienceEvidenceState::Throttled,
        AwsResilienceHubTransportError::NotFound => ResilienceEvidenceState::NotFound,
        AwsResilienceHubTransportError::BlockedEnv
        | AwsResilienceHubTransportError::BadRequest
        | AwsResilienceHubTransportError::ServerError { .. }
        | AwsResilienceHubTransportError::Timeout
        | AwsResilienceHubTransportError::InvalidResponse => ResilienceEvidenceState::Unknown,
        AwsResilienceHubTransportError::Drift => ResilienceEvidenceState::Drifted,
        AwsResilienceHubTransportError::Partial
        | AwsResilienceHubTransportError::PaginationLoop => ResilienceEvidenceState::Partial,
    }
}

fn state_from_metadata(
    assessment: &AssessmentMetadata,
    application: &ApplicationProjection,
    observed_at: DateTime<Utc>,
) -> ResilienceEvidenceState {
    if assessment.is_expired_at(observed_at)
        || assessment.is_stale_at(observed_at)
        || application.is_expired_at(observed_at)
    {
        return ResilienceEvidenceState::Expired;
    }
    if matches!(assessment.drift(), DriftStatus::Detected)
        || matches!(application.drift(), DriftStatus::Detected)
    {
        return ResilienceEvidenceState::Drifted;
    }
    if matches!(assessment.drift(), DriftStatus::Unknown)
        || matches!(application.drift(), DriftStatus::Unknown)
    {
        return ResilienceEvidenceState::Unknown;
    }
    match assessment.status() {
        crate::model::AssessmentStatus::Pending | crate::model::AssessmentStatus::InProgress => {
            ResilienceEvidenceState::InProgress
        }
        crate::model::AssessmentStatus::Failed => ResilienceEvidenceState::Failed,
        crate::model::AssessmentStatus::Expired => ResilienceEvidenceState::Expired,
        crate::model::AssessmentStatus::Unknown => ResilienceEvidenceState::Unknown,
        crate::model::AssessmentStatus::Succeeded => {
            if assessment.resiliency_score().is_none()
                || matches!(
                    assessment.rpo_rto().rpo,
                    crate::model::PostureStatus::Unknown
                )
                || matches!(
                    assessment.rpo_rto().rto,
                    crate::model::PostureStatus::Unknown
                )
            {
                ResilienceEvidenceState::Unknown
            } else {
                match assessment.compliance_status() {
                    ComplianceStatus::Compliant => ResilienceEvidenceState::Compliant,
                    ComplianceStatus::NonCompliant => ResilienceEvidenceState::NonCompliant,
                    ComplianceStatus::Unknown => ResilienceEvidenceState::Unknown,
                }
            }
        }
    }
}
