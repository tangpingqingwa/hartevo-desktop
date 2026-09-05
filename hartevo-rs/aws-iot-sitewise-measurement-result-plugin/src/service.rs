//! Typed service, bounded proposal compilation, verification, and registration.

use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::consumer::MissionAwsIoTSiteWiseConsumer;
use crate::error::{AwsIoTSiteWiseMeasurementError, Result};
use crate::model::{
    AwsIoTSiteWiseMeasurementScope, ConsentScope, Cursor, Digest, EvidenceDigests,
    MeasurementAggregate, MeasurementEvidenceState, PermissionSnapshot, ProjectProjection,
    SecretReference, TransportProvenance, mission_projection, project_projection,
    work_product_projection,
};
use crate::provider::{
    AwsIoTSiteWiseOperation, AwsIoTSiteWiseProvider, AwsIoTSiteWiseProviderDefinition,
    AwsIoTSiteWiseTransport, DescribeAssetPropertyRequest, DescribeAssetRequest,
    GetAssetPropertyValueHistoryRequest, ListAssetsRequest,
};
use crate::{
    CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_VERSION, PLUGIN_ID, PLUGIN_VERSION, PROVIDER_ID,
    SERVICE_ID, contract_digest,
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
            "aws-iot-sitewise-registration-transition/v1",
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
pub struct AwsIoTSiteWiseMeasurementRegistration {
    id: String,
    plugin_id: String,
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    provider_revision: u64,
    provider_release: String,
    provider_digest: Digest,
    permission_snapshot: PermissionSnapshot,
    consent: ConsentScope,
    scope: AwsIoTSiteWiseMeasurementScope,
    scope_digest: Digest,
    secret_reference: SecretReference,
    registration_revision: u64,
    status: RegistrationStatus,
    registration_digest: Digest,
}

impl AwsIoTSiteWiseMeasurementRegistration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        scope: AwsIoTSiteWiseMeasurementScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        consent: ConsentScope,
        provider: &AwsIoTSiteWiseProviderDefinition,
        registration_revision: u64,
    ) -> Result<Self> {
        let id = id.into();
        if id.is_empty() || id.len() > crate::MAX_IDENTIFIER_BYTES || registration_revision == 0 {
            return Err(AwsIoTSiteWiseMeasurementError::InvalidRegistration);
        }
        let mut registration = Self {
            id,
            plugin_id: PLUGIN_ID.to_owned(),
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
            registration_digest: Digest::from_text("unsealed-aws-iot-sitewise-registration"),
        };
        registration.registration_digest = registration.calculate_digest();
        registration.validate()?;
        Ok(registration)
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn plugin_id(&self) -> &str {
        &self.plugin_id
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

    pub fn scope(&self) -> &AwsIoTSiteWiseMeasurementScope {
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
        if self.id.is_empty()
            || self.plugin_id != PLUGIN_ID
            || self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest.as_str() != CONTRACT_DIGEST
            || self.contract_digest.as_str() != contract_digest()
            || self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.provider_release.is_empty()
            || self.registration_revision == 0
            || self.scope_digest != self.scope.digest()
            || self.registration_digest != self.calculate_digest()
        {
            return Err(AwsIoTSiteWiseMeasurementError::InvalidRegistration);
        }
        self.permission_snapshot.validate()?;
        self.consent.validate()?;
        if self.permission_snapshot.permissions != PermissionSnapshot::allowlisted().permissions
            || self
                .permission_snapshot
                .permissions
                .iter()
                .any(|permission| !self.consent.permissions().contains(permission))
        {
            return Err(AwsIoTSiteWiseMeasurementError::InvalidConsent);
        }
        self.scope.validate()?;
        self.secret_reference.validate(&self.scope)?;
        self.provider_digest.validate()?;
        let expected_provider_digest = Digest::from_parts(
            "aws-iot-sitewise-provider/v1",
            &[
                ("provider_id", self.provider_id.clone()),
                ("revision", self.provider_revision.to_string()),
                ("api_revision", crate::PROVIDER_API_REVISION.to_owned()),
                ("contract", self.contract_version.clone()),
                ("release", self.provider_release.clone()),
                (
                    "capability",
                    Digest::from_parts(
                        "aws-iot-sitewise-provider-capabilities/v1",
                        &crate::LAYER1_PERMISSIONS
                            .iter()
                            .map(|permission| ("permission", (*permission).to_owned()))
                            .chain(
                                [
                                    "ListAssets",
                                    "DescribeAsset",
                                    "DescribeAssetProperty",
                                    "GetAssetPropertyValueHistory",
                                ]
                                .into_iter()
                                .map(|operation| ("operation", operation.to_owned())),
                            )
                            .collect::<Vec<_>>(),
                    )
                    .as_str()
                    .to_owned(),
                ),
                ("connected", "false".to_owned()),
                ("native", "false".to_owned()),
                ("first_party", "false".to_owned()),
            ],
        );
        if self.provider_digest != expected_provider_digest {
            return Err(AwsIoTSiteWiseMeasurementError::ProviderDrift);
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsIoTSiteWiseMeasurementError::RegistrationReversed);
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
            return Err(AwsIoTSiteWiseMeasurementError::RegistrationReversed);
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
            return Err(AwsIoTSiteWiseMeasurementError::RegistrationReversed);
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
            "aws-iot-sitewise-registration/v1",
            &[
                ("id", self.id.clone()),
                ("plugin_id", self.plugin_id.clone()),
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

impl fmt::Debug for AwsIoTSiteWiseMeasurementRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsIoTSiteWiseMeasurementRegistration")
            .field("id", &Digest::from_text(&self.id))
            .field("plugin_id", &self.plugin_id)
            .field("plugin_version", &self.plugin_version)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider_id", &self.provider_id)
            .field("provider_revision", &self.provider_revision)
            .field("provider_release", &self.provider_release)
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

impl Serialize for AwsIoTSiteWiseMeasurementRegistration {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AwsIoTSiteWiseMeasurementRegistration", 15)?;
        state.serialize_field("idDigest", &Digest::from_text(&self.id))?;
        state.serialize_field("pluginId", &self.plugin_id)?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("providerRelease", &self.provider_release)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("permissionDigest", &self.permission_digest())?;
        state.serialize_field("consentDigest", &self.consent_digest())?;
        state.serialize_field("scope", &self.scope)?;
        state.serialize_field("secretReferenceDigest", &self.secret_reference_digest())?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("registrationDigest", &self.registration_digest)?;
        state.end()
    }
}

pub type AwsIoTSiteWiseRegistration = AwsIoTSiteWiseMeasurementRegistration;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityDescription {
    pub plugin_id: String,
    pub plugin_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub operations: Vec<String>,
    pub permissions: Vec<String>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MeasurementEvidenceRequest {
    pub scope_digest: Digest,
    pub observed_at: DateTime<Utc>,
    pub request_digest: Digest,
}

impl MeasurementEvidenceRequest {
    pub fn new(scope: &AwsIoTSiteWiseMeasurementScope, observed_at: DateTime<Utc>) -> Result<Self> {
        let request_digest = Digest::from_parts(
            "aws-iot-sitewise-measurement-evidence-request/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("observed_at", observed_at.to_rfc3339()),
            ],
        );
        Ok(Self {
            scope_digest: scope.digest(),
            observed_at,
            request_digest,
        })
    }

    pub fn digest(&self) -> &Digest {
        &self.request_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailureEvidence {
    pub operation: String,
    pub category: String,
    pub error_digest: Digest,
}

impl FailureEvidence {
    fn from_error(
        operation: AwsIoTSiteWiseOperation,
        error: &AwsIoTSiteWiseMeasurementError,
    ) -> Self {
        let category = match error {
            AwsIoTSiteWiseMeasurementError::Transport(transport) => transport.category().to_owned(),
            AwsIoTSiteWiseMeasurementError::PointLimitExceeded
            | AwsIoTSiteWiseMeasurementError::ResponseTooLarge => "partial_bound".to_owned(),
            AwsIoTSiteWiseMeasurementError::TamperedEvidence
            | AwsIoTSiteWiseMeasurementError::ScopeMismatch
            | AwsIoTSiteWiseMeasurementError::MeasurementFenceViolation
            | AwsIoTSiteWiseMeasurementError::OrderingViolation => "tampered".to_owned(),
            _ => "provider_unknown".to_owned(),
        };
        Self {
            operation: operation.as_str().to_owned(),
            category,
            error_digest: Digest::from_text(error.to_string()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsIoTSiteWiseMeasurementProposal {
    pub service_id: String,
    pub consumer_id: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub mission: crate::model::MissionProjection,
    pub project: ProjectProjection,
    pub work_product: crate::model::WorkProductProjection,
    pub state: MeasurementEvidenceState,
    pub aggregate: Option<MeasurementAggregate>,
    pub evidence: EvidenceDigests,
    pub failure: Option<FailureEvidence>,
    pub provenance: TransportProvenance,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub proposal_digest: Digest,
}

impl AwsIoTSiteWiseMeasurementProposal {
    fn new(
        registration: &AwsIoTSiteWiseMeasurementRegistration,
        state: MeasurementEvidenceState,
        aggregate: Option<MeasurementAggregate>,
        evidence: EvidenceDigests,
        failure: Option<FailureEvidence>,
        provenance: TransportProvenance,
    ) -> Self {
        let mut evidence = evidence;
        evidence.evidence_digest = calculate_evidence_digest(&evidence);
        let mut proposal = Self {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            registration_digest: registration.registration_digest().clone(),
            scope_digest: registration.scope_digest().clone(),
            mission: mission_projection(registration.scope().mission()),
            project: project_projection(registration.scope().project()),
            work_product: work_product_projection(registration.scope().work_product()),
            state,
            aggregate,
            evidence,
            failure,
            provenance,
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            proposal_digest: Digest::from_text("unsealed-aws-iot-sitewise-proposal"),
        };
        proposal.proposal_digest = proposal.calculate_digest();
        proposal
    }

    fn revoked(registration: &AwsIoTSiteWiseMeasurementRegistration) -> Self {
        let evidence = empty_evidence(registration);
        Self::new(
            registration,
            MeasurementEvidenceState::Revoked,
            None,
            evidence,
            Some(FailureEvidence {
                operation: "registration".to_owned(),
                category: "revoked".to_owned(),
                error_digest: Digest::from_text("registration-revoked"),
            }),
            TransportProvenance::BlockedEnv,
        )
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.service_id != SERVICE_ID
            || self.consumer_id != CONSUMER_ID
            || !self.review_only
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.provenance.is_native()
            || self.provenance.is_connected()
            || self.provenance.is_first_party()
            || self.proposal_digest != self.calculate_digest()
        {
            return Err(AwsIoTSiteWiseMeasurementError::TamperedEvidence);
        }
        self.evidence.validate()?;
        if let Some(aggregate) = &self.aggregate {
            aggregate.validate()?;
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
            "aws-iot-sitewise-measurement-proposal/v1",
            &[
                ("service", self.service_id.clone()),
                ("consumer", self.consumer_id.clone()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("mission", self.mission.id_digest.as_str().to_owned()),
                ("project", self.project.id_digest.as_str().to_owned()),
                (
                    "work_product",
                    self.work_product.id_digest.as_str().to_owned(),
                ),
                ("state", format!("{:?}", self.state)),
                (
                    "aggregate",
                    self.aggregate
                        .as_ref()
                        .map_or_else(String::new, |aggregate| {
                            aggregate.aggregate_digest.as_str().to_owned()
                        }),
                ),
                (
                    "evidence",
                    self.evidence.evidence_digest.as_str().to_owned(),
                ),
                (
                    "failure",
                    self.failure.as_ref().map_or_else(String::new, |failure| {
                        format!(
                            "{}:{}:{}",
                            failure.operation,
                            failure.category,
                            failure.error_digest.as_str()
                        )
                    }),
                ),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFailure {
    InvalidProposal,
    EvidenceDigest,
    Registration,
    Scope,
    ProviderDrift,
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
            "aws-iot-sitewise-verification-report/v1",
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

pub struct AwsIoTSiteWiseMeasurementService<T: AwsIoTSiteWiseTransport> {
    scope: AwsIoTSiteWiseMeasurementScope,
    registration: AwsIoTSiteWiseMeasurementRegistration,
    provider: AwsIoTSiteWiseProvider<T>,
    observed_at: DateTime<Utc>,
}

impl<T: AwsIoTSiteWiseTransport> fmt::Debug for AwsIoTSiteWiseMeasurementService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsIoTSiteWiseMeasurementService")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest(),
            )
            .field("provider", &self.provider)
            .field("observed_at", &self.observed_at)
            .finish()
    }
}

impl<T: AwsIoTSiteWiseTransport> AwsIoTSiteWiseMeasurementService<T> {
    pub fn new(
        scope: AwsIoTSiteWiseMeasurementScope,
        secret_reference: SecretReference,
        consent: ConsentScope,
        provider: AwsIoTSiteWiseProvider<T>,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        let registration = AwsIoTSiteWiseMeasurementRegistration::new(
            "aws-iot-sitewise-measurement-registration",
            scope.clone(),
            secret_reference,
            PermissionSnapshot::allowlisted(),
            consent,
            provider.definition(),
            1,
        )?;
        Ok(Self {
            scope,
            registration,
            provider,
            observed_at,
        })
    }

    pub fn with_registration(
        scope: AwsIoTSiteWiseMeasurementScope,
        registration: AwsIoTSiteWiseMeasurementRegistration,
        provider: AwsIoTSiteWiseProvider<T>,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        registration.validate()?;
        if registration.scope_digest() != &scope.digest() {
            return Err(AwsIoTSiteWiseMeasurementError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            provider,
            observed_at,
        })
    }

    pub fn scope(&self) -> &AwsIoTSiteWiseMeasurementScope {
        &self.scope
    }

    pub fn registration(&self) -> &AwsIoTSiteWiseMeasurementRegistration {
        &self.registration
    }

    pub fn provider(&self) -> &AwsIoTSiteWiseProvider<T> {
        &self.provider
    }

    pub fn default_request(
        &self,
        observed_at: DateTime<Utc>,
    ) -> Result<MeasurementEvidenceRequest> {
        MeasurementEvidenceRequest::new(&self.scope, observed_at)
    }

    pub fn describe_capabilities(&self) -> CapabilityDescription {
        CapabilityDescription {
            plugin_id: PLUGIN_ID.to_owned(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            operations: [
                AwsIoTSiteWiseOperation::ListAssets,
                AwsIoTSiteWiseOperation::DescribeAsset,
                AwsIoTSiteWiseOperation::DescribeAssetProperty,
                AwsIoTSiteWiseOperation::GetAssetPropertyValueHistory,
            ]
            .into_iter()
            .map(|operation| operation.as_str().to_owned())
            .collect(),
            permissions: crate::LAYER1_PERMISSIONS
                .iter()
                .map(|permission| (*permission).to_owned())
                .collect(),
            read_only: true,
            proposal_only: true,
            connected: false,
            native: false,
            first_party: false,
        }
    }

    pub fn propose(
        &mut self,
        request: MeasurementEvidenceRequest,
    ) -> Result<AwsIoTSiteWiseMeasurementProposal> {
        if request.scope_digest != self.scope.digest() {
            return Err(AwsIoTSiteWiseMeasurementError::ScopeMismatch);
        }
        if !self.registration.is_active() {
            return Ok(AwsIoTSiteWiseMeasurementProposal::revoked(
                &self.registration,
            ));
        }
        let provenance = self.provider.provenance();
        let mut evidence = empty_evidence(&self.registration);

        let mut list_cursor = None;
        let mut list_page_digests = Vec::new();
        let mut asset_found = false;
        for page_index in 0..self.scope.bounds().max_pages {
            let list_request = ListAssetsRequest::for_scope(&self.scope, list_cursor.clone())?;
            let response = match self.provider.list_assets(&list_request) {
                Ok(response) => response,
                Err(error) => {
                    return Ok(self.failure_proposal(
                        MeasurementEvidenceState::from_error(&error),
                        evidence,
                        FailureEvidence::from_error(AwsIoTSiteWiseOperation::ListAssets, &error),
                        provenance,
                    ));
                }
            };
            list_page_digests.push(response.evidence_digest.clone());
            if response.assets.iter().any(|asset| {
                asset.asset_id_digest == self.scope.asset_id().digest()
                    && asset.asset_model_id_digest == self.scope.asset_model_id().digest()
            }) {
                asset_found = true;
                break;
            }
            match response.next_cursor {
                Some(cursor) if page_index + 1 < self.scope.bounds().max_pages => {
                    list_cursor = Some(cursor);
                }
                Some(_) => {
                    evidence.list_assets_digest =
                        Some(fold_digests("list-assets", &list_page_digests));
                    return Ok(self.failure_proposal(
                        MeasurementEvidenceState::Partial,
                        evidence,
                        FailureEvidence {
                            operation: AwsIoTSiteWiseOperation::ListAssets.as_str().to_owned(),
                            category: "page_bound".to_owned(),
                            error_digest: Digest::from_text("list-assets-page-bound"),
                        },
                        provenance,
                    ));
                }
                None => break,
            }
        }
        evidence.list_assets_digest = Some(fold_digests("list-assets", &list_page_digests));
        if !asset_found {
            return Ok(self.proposal(
                MeasurementEvidenceState::Empty,
                None,
                evidence,
                None,
                provenance,
            ));
        }

        let describe_request = DescribeAssetRequest::for_scope(&self.scope)?;
        let describe = match self.provider.describe_asset(&describe_request) {
            Ok(response) => response,
            Err(error) => {
                return Ok(self.failure_proposal(
                    MeasurementEvidenceState::from_error(&error),
                    evidence,
                    FailureEvidence::from_error(AwsIoTSiteWiseOperation::DescribeAsset, &error),
                    provenance,
                ));
            }
        };
        evidence.describe_asset_digest = Some(describe.evidence_digest.clone());

        let property_request = DescribeAssetPropertyRequest::for_scope(&self.scope)?;
        let property = match self.provider.describe_asset_property(&property_request) {
            Ok(response) => response,
            Err(error) => {
                return Ok(self.failure_proposal(
                    MeasurementEvidenceState::from_error(&error),
                    evidence,
                    FailureEvidence::from_error(
                        AwsIoTSiteWiseOperation::DescribeAssetProperty,
                        &error,
                    ),
                    provenance,
                ));
            }
        };
        evidence.describe_property_digest = Some(property.evidence_digest.clone());

        let mut history_cursor: Option<Cursor> = None;
        let mut history_page_digests = Vec::new();
        let mut points = Vec::new();
        let mut page_aggregates = Vec::new();
        let mut partial = false;
        for page_index in 0..self.scope.bounds().max_pages {
            let history_request = GetAssetPropertyValueHistoryRequest::for_scope(
                &self.scope,
                history_cursor.clone(),
            )?;
            let response = match self
                .provider
                .get_asset_property_value_history(&history_request)
            {
                Ok(response) => response,
                Err(error) => {
                    return Ok(self.failure_proposal(
                        MeasurementEvidenceState::from_error(&error),
                        evidence,
                        FailureEvidence::from_error(
                            AwsIoTSiteWiseOperation::GetAssetPropertyValueHistory,
                            &error,
                        ),
                        provenance,
                    ));
                }
            };
            history_page_digests.push(response.evidence_digest.clone());
            points.extend(response.points.clone());
            page_aggregates.push(response.aggregate.clone());
            if points.len() > self.scope.bounds().max_points as usize {
                partial = true;
                break;
            }
            match response.next_cursor {
                Some(cursor) if page_index + 1 < self.scope.bounds().max_pages => {
                    history_cursor = Some(cursor);
                }
                Some(_) => {
                    partial = true;
                    break;
                }
                None => break,
            }
        }
        evidence.history_digest = Some(fold_digests("history", &history_page_digests));
        let aggregate = if points.is_empty() {
            None
        } else {
            Some(MeasurementAggregate::merge(&page_aggregates, &points))
        };
        let state = if partial {
            MeasurementEvidenceState::Partial
        } else if aggregate.is_none() {
            MeasurementEvidenceState::Empty
        } else if request.observed_at
            > self.scope.time_window().end
                + chrono::Duration::seconds(self.scope.bounds().stale_after_seconds)
        {
            MeasurementEvidenceState::Stale
        } else {
            MeasurementEvidenceState::Present
        };
        Ok(self.proposal(state, aggregate, evidence, None, provenance))
    }

    pub fn verify(&self, proposal: &AwsIoTSiteWiseMeasurementProposal) -> VerificationReport {
        let mut failures = Vec::new();
        if proposal.validate_integrity().is_err() {
            failures.push(VerificationFailure::InvalidProposal);
        }
        if proposal.registration_digest != *self.registration.registration_digest() {
            failures.push(VerificationFailure::Registration);
        }
        if proposal.scope_digest != self.scope.digest()
            || proposal.mission != mission_projection(self.scope.mission())
            || proposal.project != project_projection(self.scope.project())
            || proposal.work_product != work_product_projection(self.scope.work_product())
        {
            failures.push(VerificationFailure::Scope);
        }
        if proposal.evidence.contract_digest.as_str() != CONTRACT_DIGEST
            || proposal.evidence.plugin_version_digest != Digest::from_text(PLUGIN_VERSION)
        {
            failures.push(VerificationFailure::EvidenceDigest);
        }
        let valid = failures.is_empty();
        VerificationReport::new(
            valid,
            valid && proposal.state != MeasurementEvidenceState::Revoked,
            failures,
        )
    }

    pub fn consumer(&self) -> Result<MissionAwsIoTSiteWiseConsumer> {
        MissionAwsIoTSiteWiseConsumer::new(self.scope.clone(), self.registration.clone())
    }

    pub fn revoke_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.revoke()
    }

    pub fn reverse_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.reverse()
    }

    pub fn restore_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.restore()
    }

    fn proposal(
        &self,
        state: MeasurementEvidenceState,
        aggregate: Option<MeasurementAggregate>,
        evidence: EvidenceDigests,
        failure: Option<FailureEvidence>,
        provenance: TransportProvenance,
    ) -> AwsIoTSiteWiseMeasurementProposal {
        AwsIoTSiteWiseMeasurementProposal::new(
            &self.registration,
            state,
            aggregate,
            evidence,
            failure,
            provenance,
        )
    }

    fn failure_proposal(
        &self,
        state: MeasurementEvidenceState,
        evidence: EvidenceDigests,
        failure: FailureEvidence,
        provenance: TransportProvenance,
    ) -> AwsIoTSiteWiseMeasurementProposal {
        self.proposal(state, None, evidence, Some(failure), provenance)
    }
}

fn empty_evidence(registration: &AwsIoTSiteWiseMeasurementRegistration) -> EvidenceDigests {
    let mut evidence = EvidenceDigests {
        plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
        contract_digest: Digest::parse(CONTRACT_DIGEST)
            .expect("contract digest is a checked hexadecimal digest"),
        provider_digest: registration.provider_digest().clone(),
        permission_digest: registration.permission_digest(),
        consent_digest: registration.consent_digest(),
        scope_digest: registration.scope_digest().clone(),
        list_assets_digest: None,
        describe_asset_digest: None,
        describe_property_digest: None,
        history_digest: None,
        cursor_digest: None,
        evidence_digest: Digest::from_text("unsealed-aws-iot-sitewise-evidence"),
    };
    evidence.evidence_digest = calculate_evidence_digest(&evidence);
    evidence
}

fn calculate_evidence_digest(evidence: &EvidenceDigests) -> Digest {
    Digest::from_parts(
        "aws-iot-sitewise-evidence-digests/v1",
        &[
            ("plugin", evidence.plugin_version_digest.as_str().to_owned()),
            ("contract", evidence.contract_digest.as_str().to_owned()),
            ("provider", evidence.provider_digest.as_str().to_owned()),
            ("permission", evidence.permission_digest.as_str().to_owned()),
            ("consent", evidence.consent_digest.as_str().to_owned()),
            ("scope", evidence.scope_digest.as_str().to_owned()),
            (
                "list_assets",
                evidence
                    .list_assets_digest
                    .as_ref()
                    .map_or_else(String::new, |digest| digest.as_str().to_owned()),
            ),
            (
                "describe_asset",
                evidence
                    .describe_asset_digest
                    .as_ref()
                    .map_or_else(String::new, |digest| digest.as_str().to_owned()),
            ),
            (
                "describe_property",
                evidence
                    .describe_property_digest
                    .as_ref()
                    .map_or_else(String::new, |digest| digest.as_str().to_owned()),
            ),
            (
                "history",
                evidence
                    .history_digest
                    .as_ref()
                    .map_or_else(String::new, |digest| digest.as_str().to_owned()),
            ),
            (
                "cursor",
                evidence
                    .cursor_digest
                    .as_ref()
                    .map_or_else(String::new, |digest| digest.as_str().to_owned()),
            ),
        ],
    )
}

fn validate_evidence_digests(evidence: &EvidenceDigests) -> Result<()> {
    evidence.plugin_version_digest.validate()?;
    evidence.contract_digest.validate()?;
    evidence.provider_digest.validate()?;
    evidence.permission_digest.validate()?;
    evidence.consent_digest.validate()?;
    evidence.scope_digest.validate()?;
    for digest in [
        evidence.list_assets_digest.as_ref(),
        evidence.describe_asset_digest.as_ref(),
        evidence.describe_property_digest.as_ref(),
        evidence.history_digest.as_ref(),
        evidence.cursor_digest.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        digest.validate()?;
    }
    if evidence.evidence_digest != calculate_evidence_digest(evidence) {
        return Err(AwsIoTSiteWiseMeasurementError::TamperedEvidence);
    }
    Ok(())
}

impl EvidenceDigests {
    fn validate(&self) -> Result<()> {
        validate_evidence_digests(self)
    }
}

impl MeasurementEvidenceState {
    fn from_error(error: &AwsIoTSiteWiseMeasurementError) -> Self {
        match error {
            AwsIoTSiteWiseMeasurementError::Transport(transport) if transport.is_access_loss() => {
                Self::AccessLost
            }
            AwsIoTSiteWiseMeasurementError::PointLimitExceeded
            | AwsIoTSiteWiseMeasurementError::ResponseTooLarge => Self::Partial,
            AwsIoTSiteWiseMeasurementError::TamperedEvidence
            | AwsIoTSiteWiseMeasurementError::ScopeMismatch
            | AwsIoTSiteWiseMeasurementError::MeasurementFenceViolation
            | AwsIoTSiteWiseMeasurementError::OrderingViolation => Self::Tampered,
            _ => Self::ProviderUnknown,
        }
    }
}

fn fold_digests(domain: &str, digests: &[Digest]) -> Digest {
    Digest::from_parts(
        &format!("aws-iot-sitewise-{domain}-pages/v1"),
        &[(
            "pages",
            digests
                .iter()
                .map(Digest::as_str)
                .collect::<Vec<_>>()
                .join("\n"),
        )],
    )
}
