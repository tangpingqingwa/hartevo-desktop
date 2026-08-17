use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::consumer::MissionAwsCloudFrontConsumer;
use crate::error::{AwsCloudFrontDistributionError, AwsCloudFrontTransportError, Result};
use crate::model::{
    AwsCloudFrontDistributionScope, CloudFrontEvidenceState, ConsentScope, CostReceipt,
    CostSummary, DeploymentProjection, Digest, DistributionProjection, DistributionSummary,
    EvidenceDigests, MissionProjection, PermissionSnapshot, ProjectProjection, RequestReceipt,
    SecretReference, TransportProvenance, deployment_projection, mission_projection,
    project_projection,
};
use crate::provider::{
    AwsCloudFrontOperation, AwsCloudFrontProvider, AwsCloudFrontProviderDefinition,
    AwsCloudFrontTransport, GetDistributionConfigRequest, GetDistributionRequest,
    ListDistributionsRequest,
};
use crate::{
    API_REVISION, CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_VERSION, MAX_PAGES, PLUGIN_VERSION,
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
            "aws-cloudfront-registration-transition/v1",
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
pub struct AwsCloudFrontDistributionRegistration {
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
    scope: AwsCloudFrontDistributionScope,
    scope_digest: Digest,
    secret_reference: SecretReference,
    registration_revision: u64,
    status: RegistrationStatus,
    binding_digest: Digest,
}

impl AwsCloudFrontDistributionRegistration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        scope: AwsCloudFrontDistributionScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        consent: ConsentScope,
        provider: &AwsCloudFrontProviderDefinition,
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
            binding_digest: Digest::from_text("unsealed-aws-cloudfront-registration"),
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

    pub fn scope(&self) -> &AwsCloudFrontDistributionScope {
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
            return Err(AwsCloudFrontDistributionError::InvalidRegistration);
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
            return Err(AwsCloudFrontDistributionError::InvalidConsent);
        }
        self.consent.validate()
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsCloudFrontDistributionError::RegistrationReversed);
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
            return Err(AwsCloudFrontDistributionError::RegistrationReversed);
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
            return Err(AwsCloudFrontDistributionError::RegistrationReversed);
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
            "aws-cloudfront-registration/v1",
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
                (
                    "distribution",
                    self.scope.distribution().digest().as_str().to_owned(),
                ),
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

pub type AwsCloudFrontRegistration = AwsCloudFrontDistributionRegistration;

impl fmt::Debug for AwsCloudFrontDistributionRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsCloudFrontDistributionRegistration")
            .field("id", &Digest::from_text(&self.id))
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

impl Serialize for AwsCloudFrontDistributionRegistration {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AwsCloudFrontDistributionRegistration", 19)?;
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
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudFrontEvidenceRequest {
    pub scope_digest: Digest,
    pub page_size: u16,
    pub max_pages: u16,
    pub expected_provider_digest: Digest,
    pub expected_registration_digest: Digest,
    pub observed_at: DateTime<Utc>,
}

impl CloudFrontEvidenceRequest {
    pub fn new(
        scope: &AwsCloudFrontDistributionScope,
        page_size: u16,
        max_pages: u16,
        expected_provider_digest: Digest,
        expected_registration_digest: Digest,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        crate::model::validate_page_size(page_size)?;
        if max_pages == 0 || max_pages > MAX_PAGES {
            return Err(AwsCloudFrontDistributionError::InvalidRequest);
        }
        expected_provider_digest.validate()?;
        expected_registration_digest.validate()?;
        scope.validate()?;
        Ok(Self {
            scope_digest: scope.digest(),
            page_size,
            max_pages,
            expected_provider_digest,
            expected_registration_digest,
            observed_at,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "aws-cloudfront-evidence-request/v1",
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
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailureEvidence {
    pub operation: AwsCloudFrontOperation,
    pub status_code: Option<u16>,
    pub category: String,
    pub failure_digest: Digest,
}

impl FailureEvidence {
    fn from_transport(
        operation: AwsCloudFrontOperation,
        error: &AwsCloudFrontTransportError,
    ) -> Self {
        let category = match error {
            AwsCloudFrontTransportError::BlockedEnv => "blocked_env",
            AwsCloudFrontTransportError::BadRequest => "bad_request",
            AwsCloudFrontTransportError::Unauthorized => "unauthorized",
            AwsCloudFrontTransportError::Forbidden => "forbidden",
            AwsCloudFrontTransportError::NotFound => "not_found",
            AwsCloudFrontTransportError::Conflict => "conflict",
            AwsCloudFrontTransportError::RateLimited { .. } => "throttled",
            AwsCloudFrontTransportError::ServerError { .. } => "server_error",
            AwsCloudFrontTransportError::Timeout => "timeout",
            AwsCloudFrontTransportError::AccessLost => "access_loss",
            AwsCloudFrontTransportError::Partial => "partial",
            AwsCloudFrontTransportError::Unknown => "provider_unknown",
            AwsCloudFrontTransportError::InvalidResponse => "invalid_response",
            AwsCloudFrontTransportError::Tampered => "tampered",
            AwsCloudFrontTransportError::ConfigDrift => "config_drift",
            AwsCloudFrontTransportError::PaginationLoop => "pagination_loop",
        }
        .to_owned();
        let failure_digest = Digest::from_parts(
            "aws-cloudfront-failure/v1",
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
pub struct AwsCloudFrontDistributionProposal {
    pub service_id: String,
    pub consumer_id: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub account_digest: Digest,
    pub region_digest: Digest,
    pub distribution_digest: Digest,
    pub mission: MissionProjection,
    pub project: ProjectProjection,
    pub deployment: DeploymentProjection,
    pub state: CloudFrontEvidenceState,
    pub list_pages: u16,
    pub list_complete: bool,
    pub distribution: Option<DistributionProjection>,
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

impl AwsCloudFrontDistributionProposal {
    fn new(
        registration: &AwsCloudFrontDistributionRegistration,
        provider: &AwsCloudFrontProviderDefinition,
        request: &CloudFrontEvidenceRequest,
        state: CloudFrontEvidenceState,
        list_pages: u16,
        list_complete: bool,
        list_digest: Option<Digest>,
        get_digest: Option<Digest>,
        config_digest: Option<Digest>,
        distribution: Option<DistributionProjection>,
        failure: Option<FailureEvidence>,
        request_receipts: Vec<RequestReceipt>,
        cost_receipts: Vec<CostReceipt>,
        provenance: TransportProvenance,
    ) -> Self {
        let distribution_digest = registration.scope().distribution().digest();
        let mut evidence = EvidenceDigests {
            plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_digest: registration.contract_digest.clone(),
            provider_digest: provider.provider_digest.clone(),
            api_digest: registration.api_digest.clone(),
            permission_digest: registration.permission_digest(),
            scope_digest: registration.scope_digest.clone(),
            distribution_digest: distribution_digest.clone(),
            list_digest,
            get_digest,
            config_digest,
            evidence_digest: Digest::from_text("unsealed-aws-cloudfront-evidence"),
        };
        evidence.evidence_digest = calculate_evidence_digest(
            &evidence,
            &request.digest(),
            state,
            list_pages,
            list_complete,
            distribution.as_ref(),
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
            request_digest: request.digest(),
            account_digest: registration.scope().account().digest(),
            region_digest: registration.scope().region().digest(),
            distribution_digest,
            mission: mission_projection(registration.scope().mission()),
            project: project_projection(registration.scope().project()),
            deployment: deployment_projection(registration.scope().deployment()),
            state,
            list_pages,
            list_complete,
            distribution,
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
            proposal_digest: Digest::from_text("unsealed-aws-cloudfront-proposal"),
        };
        proposal.proposal_digest = proposal.calculate_digest();
        proposal
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.evidence.validate()?;
        self.request_digest.validate()?;
        if self.service_id != SERVICE_ID
            || self.consumer_id != CONSUMER_ID
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.availability_claim
            || self.outcome_adopted
            || self.work_product_adopted
            || self
                .request_receipts
                .iter()
                .any(|receipt| receipt.validate_integrity().is_err())
            || self
                .cost_receipts
                .iter()
                .any(|receipt| receipt.validate_integrity().is_err())
            || self.cost_summary.cost_digest
                != CostSummary::from_receipts(&self.cost_receipts).cost_digest
            || self.evidence.evidence_digest
                != calculate_evidence_digest(
                    &self.evidence,
                    &self.request_digest,
                    self.state,
                    self.list_pages,
                    self.list_complete,
                    self.distribution.as_ref(),
                    self.failure.as_ref(),
                    &self.request_receipts,
                    &self.cost_receipts,
                )
            || self.proposal_digest != self.calculate_digest()
        {
            return Err(AwsCloudFrontDistributionError::TamperedEvidence);
        }
        if let Some(distribution) = &self.distribution {
            distribution.validate_integrity()?;
            if distribution.distribution_identity_digest != self.distribution_digest {
                return Err(AwsCloudFrontDistributionError::TamperedEvidence);
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
            "aws-cloudfront-distribution-proposal/v1",
            &[
                ("service", self.service_id.clone()),
                ("consumer", self.consumer_id.clone()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("account", self.account_digest.as_str().to_owned()),
                ("region", self.region_digest.as_str().to_owned()),
                ("distribution", self.distribution_digest.as_str().to_owned()),
                (
                    "mission",
                    serde_json::to_string(&self.mission).expect("mission projection serializes"),
                ),
                (
                    "project",
                    serde_json::to_string(&self.project).expect("project projection serializes"),
                ),
                (
                    "deployment",
                    serde_json::to_string(&self.deployment)
                        .expect("deployment projection serializes"),
                ),
                ("state", format!("{:?}", self.state)),
                ("list_pages", self.list_pages.to_string()),
                ("list_complete", self.list_complete.to_string()),
                (
                    "distribution_projection",
                    self.distribution
                        .as_ref()
                        .map_or_else(String::new, |value| {
                            serde_json::to_string(value)
                                .expect("distribution projection serializes")
                        }),
                ),
                (
                    "failure",
                    self.failure.as_ref().map_or_else(String::new, |value| {
                        serde_json::to_string(value).expect("failure evidence serializes")
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
                    serde_json::to_string(&self.evidence).expect("evidence digests serialize"),
                ),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

fn calculate_evidence_digest(
    evidence: &EvidenceDigests,
    request_digest: &Digest,
    state: CloudFrontEvidenceState,
    list_pages: u16,
    list_complete: bool,
    distribution: Option<&DistributionProjection>,
    failure: Option<&FailureEvidence>,
    request_receipts: &[RequestReceipt],
    cost_receipts: &[CostReceipt],
) -> Digest {
    Digest::from_parts(
        "aws-cloudfront-evidence/v1",
        &[
            ("plugin", evidence.plugin_version_digest.as_str().to_owned()),
            ("contract", evidence.contract_digest.as_str().to_owned()),
            ("provider", evidence.provider_digest.as_str().to_owned()),
            ("api", evidence.api_digest.as_str().to_owned()),
            ("permission", evidence.permission_digest.as_str().to_owned()),
            ("scope", evidence.scope_digest.as_str().to_owned()),
            (
                "distribution",
                evidence.distribution_digest.as_str().to_owned(),
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
            (
                "config",
                evidence
                    .config_digest
                    .as_ref()
                    .map_or_else(String::new, |digest| digest.as_str().to_owned()),
            ),
            ("request", request_digest.as_str().to_owned()),
            ("state", format!("{state:?}")),
            ("list_pages", list_pages.to_string()),
            ("list_complete", list_complete.to_string()),
            (
                "projection",
                distribution.map_or_else(String::new, |value| {
                    value.projection_digest.as_str().to_owned()
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

pub struct AwsCloudFrontDistributionService<T: AwsCloudFrontTransport> {
    registration: AwsCloudFrontDistributionRegistration,
    provider: AwsCloudFrontProvider<T>,
}

impl<T: AwsCloudFrontTransport> fmt::Debug for AwsCloudFrontDistributionService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsCloudFrontDistributionService")
            .field("registration", &self.registration)
            .field("provider", &self.provider)
            .finish()
    }
}

impl<T: AwsCloudFrontTransport> AwsCloudFrontDistributionService<T> {
    pub fn new(
        scope: AwsCloudFrontDistributionScope,
        secret_reference: SecretReference,
        consent: ConsentScope,
        provider: AwsCloudFrontProvider<T>,
        _observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        let registration = AwsCloudFrontDistributionRegistration::new(
            "aws-cloudfront-distribution-registration",
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

    pub fn with_registration(
        registration: AwsCloudFrontDistributionRegistration,
        provider: AwsCloudFrontProvider<T>,
    ) -> Result<Self> {
        registration.validate()?;
        if registration.provider_digest() != &provider.definition().provider_digest {
            return Err(AwsCloudFrontDistributionError::ProviderDrift);
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
                AwsCloudFrontOperation::ListDistributions
                    .as_str()
                    .to_owned(),
                AwsCloudFrontOperation::GetDistribution.as_str().to_owned(),
                AwsCloudFrontOperation::GetDistributionConfig
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

    pub fn scope(&self) -> &AwsCloudFrontDistributionScope {
        self.registration.scope()
    }

    pub fn registration(&self) -> &AwsCloudFrontDistributionRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut AwsCloudFrontDistributionRegistration {
        &mut self.registration
    }

    pub fn provider(&self) -> &AwsCloudFrontProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsCloudFrontProvider<T> {
        &mut self.provider
    }

    pub fn default_request(&self, observed_at: DateTime<Utc>) -> Result<CloudFrontEvidenceRequest> {
        CloudFrontEvidenceRequest::new(
            self.scope(),
            crate::MAX_PAGE_SIZE,
            MAX_PAGES,
            self.provider.definition().provider_digest.clone(),
            self.registration.registration_digest().clone(),
            observed_at,
        )
    }

    pub fn request(
        &self,
        page_size: u16,
        max_pages: u16,
        observed_at: DateTime<Utc>,
    ) -> Result<CloudFrontEvidenceRequest> {
        CloudFrontEvidenceRequest::new(
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

    pub fn consumer(&self) -> Result<MissionAwsCloudFrontConsumer> {
        MissionAwsCloudFrontConsumer::new(self.scope().clone(), self.registration.clone())
    }

    pub fn verify(&self, proposal: &AwsCloudFrontDistributionProposal) -> VerificationReport {
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
            CloudFrontEvidenceState::AccessLoss => failures.push(VerificationFailure::AccessLoss),
            CloudFrontEvidenceState::Unauthorized => {
                failures.push(VerificationFailure::Unauthorized);
            }
            CloudFrontEvidenceState::Forbidden => failures.push(VerificationFailure::Forbidden),
            CloudFrontEvidenceState::NotFound => failures.push(VerificationFailure::NotFound),
            CloudFrontEvidenceState::Conflict => failures.push(VerificationFailure::Conflict),
            CloudFrontEvidenceState::Throttled => failures.push(VerificationFailure::Throttled),
            CloudFrontEvidenceState::TimedOut => failures.push(VerificationFailure::TimedOut),
            CloudFrontEvidenceState::ConfigDrift => failures.push(VerificationFailure::ConfigDrift),
            CloudFrontEvidenceState::PaginationLoop => {
                failures.push(VerificationFailure::PaginationLoop);
            }
            CloudFrontEvidenceState::Partial => failures.push(VerificationFailure::PartialEvidence),
            CloudFrontEvidenceState::Tampered => {
                failures.push(VerificationFailure::TamperedEvidence);
            }
            CloudFrontEvidenceState::ProviderUnknown => {
                failures.push(VerificationFailure::ProviderUnknown);
            }
            CloudFrontEvidenceState::RegistrationRevoked => {
                failures.push(VerificationFailure::RegistrationInactive);
            }
            CloudFrontEvidenceState::Ready
            | CloudFrontEvidenceState::Disabled
            | CloudFrontEvidenceState::InProgress => {}
        }
        failures.sort_unstable();
        failures.dedup();
        let valid = failures.is_empty();
        let review_eligible = valid
            && proposal.list_complete
            && proposal.distribution.is_some()
            && proposal.state.is_review_complete()
            && !proposal.connected
            && !proposal.native
            && !proposal.first_party
            && !proposal.provider_receipt;
        VerificationReport::new(valid, review_eligible, failures)
    }

    pub fn propose(
        &mut self,
        request: CloudFrontEvidenceRequest,
    ) -> Result<AwsCloudFrontDistributionProposal> {
        self.validate_request(&request)?;
        let mut list_request = ListDistributionsRequest::first(self.scope(), request.page_size)?;
        let mut seen_markers = BTreeSet::new();
        let mut request_receipts = Vec::new();
        let mut cost_receipts = Vec::new();
        let mut list_digests = Vec::new();
        let mut list_pages = list_request.page_number();
        let mut list_complete = false;
        let mut selected_summary: Option<DistributionSummary> = None;

        loop {
            match self.provider.list_distributions(&list_request) {
                Ok(response) => {
                    request_receipts.push(response.request_receipt.clone());
                    cost_receipts.push(response.cost_receipt.clone());
                    list_digests.push(response.evidence_digest.clone());
                    if response.distributions.len() > 1 {
                        return Ok(self.failed_proposal(
                            &request,
                            CloudFrontEvidenceState::ConfigDrift,
                            list_pages,
                            list_complete,
                            Some(Digest::from_parts(
                                "aws-cloudfront-list-evidence/v1",
                                &[("pages", crate::model::join_digests(list_digests))],
                            )),
                            None,
                            None,
                            None,
                            Some(FailureEvidence::from_transport(
                                AwsCloudFrontOperation::ListDistributions,
                                &AwsCloudFrontTransportError::ConfigDrift,
                            )),
                            request_receipts,
                            cost_receipts,
                        ));
                    }
                    if let Some(summary) = response.distributions.first() {
                        selected_summary = Some(summary.clone());
                    }
                    if let Some(cursor) = response.next_cursor {
                        if !seen_markers.insert(cursor.marker_digest().clone()) {
                            return Ok(self.failed_proposal(
                                &request,
                                CloudFrontEvidenceState::PaginationLoop,
                                list_pages,
                                false,
                                Some(Digest::from_parts(
                                    "aws-cloudfront-list-evidence/v1",
                                    &[("pages", crate::model::join_digests(list_digests))],
                                )),
                                None,
                                None,
                                None,
                                Some(FailureEvidence::from_transport(
                                    AwsCloudFrontOperation::ListDistributions,
                                    &AwsCloudFrontTransportError::PaginationLoop,
                                )),
                                request_receipts,
                                cost_receipts,
                            ));
                        }
                        if list_pages >= request.max_pages {
                            return Ok(self.failed_proposal(
                                &request,
                                CloudFrontEvidenceState::Partial,
                                list_pages,
                                false,
                                Some(Digest::from_parts(
                                    "aws-cloudfront-list-evidence/v1",
                                    &[("pages", crate::model::join_digests(list_digests))],
                                )),
                                None,
                                None,
                                None,
                                Some(FailureEvidence::from_transport(
                                    AwsCloudFrontOperation::ListDistributions,
                                    &AwsCloudFrontTransportError::Partial,
                                )),
                                request_receipts,
                                cost_receipts,
                            ));
                        }
                        list_request = ListDistributionsRequest::new(
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
                    let recorded = list_request.recorded_request();
                    request_receipts.push(recorded.receipt());
                    cost_receipts.push(CostReceipt::new(
                        AwsCloudFrontOperation::ListDistributions.as_str(),
                        0,
                    )?);
                    return Ok(self.failed_proposal(
                        &request,
                        state_for_transport(&error),
                        list_pages,
                        false,
                        (!list_digests.is_empty()).then(|| {
                            Digest::from_parts(
                                "aws-cloudfront-list-evidence/v1",
                                &[("pages", crate::model::join_digests(list_digests))],
                            )
                        }),
                        None,
                        None,
                        None,
                        Some(FailureEvidence::from_transport(
                            AwsCloudFrontOperation::ListDistributions,
                            &error,
                        )),
                        request_receipts,
                        cost_receipts,
                    ));
                }
            }
        }

        let list_digest = Some(Digest::from_parts(
            "aws-cloudfront-list-evidence/v1",
            &[("pages", crate::model::join_digests(list_digests))],
        ));
        let Some(summary_from_list) = selected_summary else {
            return Ok(self.failed_proposal(
                &request,
                CloudFrontEvidenceState::NotFound,
                list_pages,
                list_complete,
                list_digest,
                None,
                None,
                None,
                Some(FailureEvidence::from_transport(
                    AwsCloudFrontOperation::ListDistributions,
                    &AwsCloudFrontTransportError::NotFound,
                )),
                request_receipts,
                cost_receipts,
            ));
        };

        let get_request = GetDistributionRequest::for_scope(self.scope())?;
        let get_response = match self.provider.get_distribution(&get_request) {
            Ok(response) => response,
            Err(error) => {
                request_receipts.push(get_request.recorded_request().receipt());
                cost_receipts.push(CostReceipt::new(
                    AwsCloudFrontOperation::GetDistribution.as_str(),
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
                    Some(FailureEvidence::from_transport(
                        AwsCloudFrontOperation::GetDistribution,
                        &error,
                    )),
                    request_receipts,
                    cost_receipts,
                ));
            }
        };
        request_receipts.push(get_response.request_receipt.clone());
        cost_receipts.push(get_response.cost_receipt.clone());
        if summary_from_list.etag_digest() != get_response.distribution.etag_digest() {
            return Ok(self.failed_proposal(
                &request,
                CloudFrontEvidenceState::ConfigDrift,
                list_pages,
                list_complete,
                list_digest,
                Some(get_response.evidence_digest.clone()),
                None,
                None,
                Some(FailureEvidence::from_transport(
                    AwsCloudFrontOperation::GetDistribution,
                    &AwsCloudFrontTransportError::ConfigDrift,
                )),
                request_receipts,
                cost_receipts,
            ));
        }

        let config_request = GetDistributionConfigRequest::new(
            self.scope(),
            get_response.distribution.etag_digest().clone(),
        )?;
        let config_response = match self.provider.get_distribution_config(&config_request) {
            Ok(response) => response,
            Err(error) => {
                request_receipts.push(config_request.recorded_request().receipt());
                cost_receipts.push(CostReceipt::new(
                    AwsCloudFrontOperation::GetDistributionConfig.as_str(),
                    0,
                )?);
                return Ok(self.failed_proposal(
                    &request,
                    state_for_transport(&error),
                    list_pages,
                    list_complete,
                    list_digest,
                    Some(get_response.evidence_digest.clone()),
                    None,
                    None,
                    Some(FailureEvidence::from_transport(
                        AwsCloudFrontOperation::GetDistributionConfig,
                        &error,
                    )),
                    request_receipts,
                    cost_receipts,
                ));
            }
        };
        request_receipts.push(config_response.request_receipt.clone());
        cost_receipts.push(config_response.cost_receipt.clone());
        let projection = match DistributionProjection::from_parts(
            &get_response.distribution,
            &config_response.config,
        ) {
            Ok(projection) => projection,
            Err(_) => {
                return Ok(self.failed_proposal(
                    &request,
                    CloudFrontEvidenceState::ConfigDrift,
                    list_pages,
                    list_complete,
                    list_digest,
                    Some(get_response.evidence_digest.clone()),
                    Some(config_response.evidence_digest.clone()),
                    None,
                    Some(FailureEvidence::from_transport(
                        AwsCloudFrontOperation::GetDistributionConfig,
                        &AwsCloudFrontTransportError::ConfigDrift,
                    )),
                    request_receipts,
                    cost_receipts,
                ));
            }
        };
        let state = if !projection.enabled {
            CloudFrontEvidenceState::Disabled
        } else {
            match projection.status {
                crate::model::DistributionStatus::Deployed => CloudFrontEvidenceState::Ready,
                crate::model::DistributionStatus::InProgress => CloudFrontEvidenceState::InProgress,
                crate::model::DistributionStatus::Unknown => {
                    CloudFrontEvidenceState::ProviderUnknown
                }
            }
        };
        Ok(AwsCloudFrontDistributionProposal::new(
            &self.registration,
            self.provider.definition(),
            &request,
            state,
            list_pages,
            list_complete,
            list_digest,
            Some(get_response.evidence_digest),
            Some(config_response.evidence_digest),
            Some(projection),
            None,
            request_receipts,
            cost_receipts,
            self.provider.provenance(),
        ))
    }

    fn failed_proposal(
        &self,
        request: &CloudFrontEvidenceRequest,
        state: CloudFrontEvidenceState,
        list_pages: u16,
        list_complete: bool,
        list_digest: Option<Digest>,
        get_digest: Option<Digest>,
        config_digest: Option<Digest>,
        _projection_digest: Option<Digest>,
        failure: Option<FailureEvidence>,
        request_receipts: Vec<RequestReceipt>,
        cost_receipts: Vec<CostReceipt>,
    ) -> AwsCloudFrontDistributionProposal {
        AwsCloudFrontDistributionProposal::new(
            &self.registration,
            self.provider.definition(),
            request,
            state,
            list_pages,
            list_complete,
            list_digest,
            get_digest,
            config_digest,
            None,
            failure,
            request_receipts,
            cost_receipts,
            self.provider.provenance(),
        )
    }

    fn validate_request(&self, request: &CloudFrontEvidenceRequest) -> Result<()> {
        self.registration.validate()?;
        if !self.registration.is_active() {
            return Err(AwsCloudFrontDistributionError::RegistrationInactive);
        }
        if request.scope_digest != *self.registration.scope_digest()
            || request.expected_provider_digest != self.provider.definition().provider_digest
            || request.expected_registration_digest != *self.registration.registration_digest()
        {
            return Err(AwsCloudFrontDistributionError::ScopeMismatch);
        }
        if self.registration.secret_reference().is_revoked() {
            return Err(AwsCloudFrontDistributionError::SecretRevoked);
        }
        if self.registration.consent().is_revoked() {
            return Err(AwsCloudFrontDistributionError::ConsentRevoked);
        }
        if !self
            .registration
            .consent()
            .is_active_at(request.observed_at)
        {
            return Err(AwsCloudFrontDistributionError::ConsentExpired);
        }
        Ok(())
    }
}

fn state_for_transport(error: &AwsCloudFrontTransportError) -> CloudFrontEvidenceState {
    match error {
        AwsCloudFrontTransportError::BlockedEnv
        | AwsCloudFrontTransportError::Unknown
        | AwsCloudFrontTransportError::InvalidResponse => CloudFrontEvidenceState::ProviderUnknown,
        AwsCloudFrontTransportError::Unauthorized => CloudFrontEvidenceState::Unauthorized,
        AwsCloudFrontTransportError::Forbidden => CloudFrontEvidenceState::Forbidden,
        AwsCloudFrontTransportError::NotFound => CloudFrontEvidenceState::NotFound,
        AwsCloudFrontTransportError::Conflict => CloudFrontEvidenceState::Conflict,
        AwsCloudFrontTransportError::RateLimited { .. } => CloudFrontEvidenceState::Throttled,
        AwsCloudFrontTransportError::ServerError { .. } => CloudFrontEvidenceState::ProviderUnknown,
        AwsCloudFrontTransportError::Timeout => CloudFrontEvidenceState::TimedOut,
        AwsCloudFrontTransportError::AccessLost => CloudFrontEvidenceState::AccessLoss,
        AwsCloudFrontTransportError::Partial => CloudFrontEvidenceState::Partial,
        AwsCloudFrontTransportError::Tampered => CloudFrontEvidenceState::Tampered,
        AwsCloudFrontTransportError::ConfigDrift => CloudFrontEvidenceState::ConfigDrift,
        AwsCloudFrontTransportError::PaginationLoop => CloudFrontEvidenceState::PaginationLoop,
        AwsCloudFrontTransportError::BadRequest => CloudFrontEvidenceState::ProviderUnknown,
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFailure {
    RegistrationInactive,
    RegistrationDigestMismatch,
    ProviderDigestMismatch,
    ApiDigestMismatch,
    PermissionDigestMismatch,
    ScopeDigestMismatch,
    TamperedEvidence,
    PartialEvidence,
    AccessLoss,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    Throttled,
    TimedOut,
    ConfigDrift,
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
            "aws-cloudfront-verification-report/v1",
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
