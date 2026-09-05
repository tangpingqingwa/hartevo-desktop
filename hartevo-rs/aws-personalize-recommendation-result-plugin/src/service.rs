//! Layer-1 service, registration, proposal, and verification boundary.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::consumer::MissionAwsPersonalizeConsumer;
use crate::error::{AwsPersonalizeRecommendationError, AwsPersonalizeTransportError, Result};
use crate::model::{
    AwsPersonalizeRecommendationScope, CampaignMetadata, Digest, EvidenceDigests,
    MissionProjection, PermissionSnapshot, ProjectProjection, RecommendationEvidenceState,
    RecommendationResult, RecommenderMetadata, SecretReference, ServingTarget, TransportProvenance,
    WorkProductProjection,
};
use crate::provider::{
    AwsPersonalizeOperation, AwsPersonalizeProvider, AwsPersonalizeProviderDefinition,
    AwsPersonalizeTransport, DescribeCampaignRequest, DescribeRecommenderRequest,
    GetPersonalizedRankingRequest, GetRecommendationsRequest,
};
use crate::{
    CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_SCHEMA, CONTRACT_VERSION, MAX_RESULTS, PLUGIN_ID,
    PLUGIN_VERSION, PROVIDER_API_REVISION, PROVIDER_ID, SERVICE_ID, contract_digest,
    evidence_policy_digest, validate_contract_document,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub plugin_id: String,
    pub plugin_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub api_revision: String,
    pub read_only: bool,
    pub proposal_only: bool,
    pub live_execution: bool,
    pub external_writes: bool,
    pub contract_digest: Digest,
    pub version_digest: Digest,
}

impl Default for ServiceDefinition {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceDefinition {
    pub fn new() -> Self {
        let contract_digest = Digest::from_text(CONTRACT_DIGEST);
        let version_digest = Digest::from_parts(
            "aws-personalize-service-definition/v1",
            &[
                ("schema", CONTRACT_SCHEMA.to_owned()),
                ("contract", CONTRACT_VERSION.to_owned()),
                ("plugin", PLUGIN_VERSION.to_owned()),
                ("service", SERVICE_ID.to_owned()),
                ("provider", PROVIDER_ID.to_owned()),
                ("consumer", CONSUMER_ID.to_owned()),
                ("api", PROVIDER_API_REVISION.to_owned()),
            ],
        );
        Self {
            schema_version: CONTRACT_SCHEMA.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            plugin_id: PLUGIN_ID.to_owned(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            api_revision: PROVIDER_API_REVISION.to_owned(),
            read_only: true,
            proposal_only: true,
            live_execution: false,
            external_writes: false,
            contract_digest,
            version_digest,
        }
    }

    pub fn validate(&self) -> Result<()> {
        validate_contract_document()?;
        if self.schema_version != CONTRACT_SCHEMA
            || self.contract_version != CONTRACT_VERSION
            || self.plugin_id != PLUGIN_ID
            || self.plugin_version != PLUGIN_VERSION
            || self.service_id != SERVICE_ID
            || self.provider_id != PROVIDER_ID
            || self.consumer_id != CONSUMER_ID
            || self.api_revision != PROVIDER_API_REVISION
            || !self.read_only
            || !self.proposal_only
            || self.live_execution
            || self.external_writes
            || self.contract_digest != Digest::from_text(CONTRACT_DIGEST)
            || self.version_digest != Self::new().version_digest
            || contract_digest() != CONTRACT_DIGEST
        {
            return Err(AwsPersonalizeRecommendationError::ContractDrift);
        }
        Ok(())
    }
}

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
            "aws-personalize-registration-transition/v1",
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
pub struct AwsPersonalizeRecommendationRegistration {
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
    consent: crate::model::ConsentScope,
    scope: AwsPersonalizeRecommendationScope,
    scope_digest: Digest,
    secret_reference: SecretReference,
    evidence_policy_digest: Digest,
    registration_revision: u64,
    status: RegistrationStatus,
    registration_digest: Digest,
}

pub type AwsPersonalizeRegistration = AwsPersonalizeRecommendationRegistration;

impl AwsPersonalizeRecommendationRegistration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        scope: AwsPersonalizeRecommendationScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        consent: crate::model::ConsentScope,
        provider: &AwsPersonalizeProviderDefinition,
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
            api_digest: Digest::from_text(PROVIDER_API_REVISION),
            permission_snapshot,
            consent,
            scope_digest: scope.digest(),
            scope,
            secret_reference,
            evidence_policy_digest: evidence_policy_digest(),
            registration_revision,
            status: RegistrationStatus::Active,
            registration_digest: Digest::from_text("unsealed-aws-personalize-registration"),
        };
        registration.registration_digest = registration.calculate_registration_digest();
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

    pub fn consent(&self) -> &crate::model::ConsentScope {
        &self.consent
    }

    pub fn consent_digest(&self) -> Digest {
        self.consent.digest()
    }

    pub fn scope(&self) -> &AwsPersonalizeRecommendationScope {
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

    pub fn evidence_policy_digest(&self) -> &Digest {
        &self.evidence_policy_digest
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
            || self.api_digest != Digest::from_text(PROVIDER_API_REVISION)
            || self.registration_revision == 0
            || self.scope_digest != self.scope.digest()
            || self.evidence_policy_digest != evidence_policy_digest()
            || self.registration_digest != self.calculate_registration_digest()
        {
            return Err(AwsPersonalizeRecommendationError::InvalidRegistration);
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
            return Err(AwsPersonalizeRecommendationError::InvalidConsent);
        }
        self.consent.validate()
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsPersonalizeRecommendationError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Revoked;
        self.registration_digest = self.calculate_registration_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsPersonalizeRecommendationError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Active;
        self.registration_digest = self.calculate_registration_digest();
        self.validate()?;
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsPersonalizeRecommendationError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Reversed;
        self.registration_digest = self.calculate_registration_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    fn calculate_registration_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-personalize-registration/v1",
            &[
                ("id", self.id.clone()),
                ("plugin_version", self.plugin_version.clone()),
                ("version", self.version_digest.as_str().to_owned()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider", self.provider_id.clone()),
                ("provider_revision", self.provider_revision.to_string()),
                ("provider_release", self.provider_release.clone()),
                ("provider_digest", self.provider_digest.as_str().to_owned()),
                ("api", self.api_digest.as_str().to_owned()),
                ("permission", self.permission_digest().as_str().to_owned()),
                ("consent", self.consent_digest().as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "secret",
                    self.secret_reference.reference_digest().as_str().to_owned(),
                ),
                (
                    "evidence_policy",
                    self.evidence_policy_digest.as_str().to_owned(),
                ),
                ("revision", self.registration_revision.to_string()),
                ("status", format!("{:?}", self.status)),
            ],
        )
    }
}

impl fmt::Debug for AwsPersonalizeRecommendationRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsPersonalizeRecommendationRegistration")
            .field("id", &self.id)
            .field("plugin_version", &self.plugin_version)
            .field("version_digest", &self.version_digest)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider_id", &self.provider_id)
            .field("provider_revision", &self.provider_revision)
            .field("provider_release", &self.provider_release)
            .field("provider_digest", &self.provider_digest)
            .field("api_digest", &self.api_digest)
            .field("permission_digest", &self.permission_digest())
            .field("consent_digest", &self.consent_digest())
            .field("scope_digest", &self.scope_digest)
            .field("secret_reference", &self.secret_reference)
            .field("evidence_policy_digest", &self.evidence_policy_digest)
            .field("registration_revision", &self.registration_revision)
            .field("status", &self.status)
            .field("registration_digest", &self.registration_digest)
            .finish()
    }
}

impl Serialize for AwsPersonalizeRecommendationRegistration {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state =
            serializer.serialize_struct("AwsPersonalizeRecommendationRegistration", 18)?;
        state.serialize_field("id", &self.id)?;
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
        state.serialize_field(
            "secretReferenceDigest",
            self.secret_reference.reference_digest(),
        )?;
        state.serialize_field("secretReferenceRevision", &self.secret_reference.revision())?;
        state.serialize_field("evidencePolicyDigest", &self.evidence_policy_digest)?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("registrationDigest", &self.registration_digest)?;
        state.end()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AwsPersonalizeRecommendationRequest {
    DescribeCampaign(DescribeCampaignRequest),
    DescribeRecommender(DescribeRecommenderRequest),
    GetRecommendations(GetRecommendationsRequest),
    GetPersonalizedRanking(GetPersonalizedRankingRequest),
}

impl AwsPersonalizeRecommendationRequest {
    pub const fn operation(&self) -> AwsPersonalizeOperation {
        match self {
            Self::DescribeCampaign(_) => AwsPersonalizeOperation::DescribeCampaign,
            Self::DescribeRecommender(_) => AwsPersonalizeOperation::DescribeRecommender,
            Self::GetRecommendations(_) => AwsPersonalizeOperation::GetRecommendations,
            Self::GetPersonalizedRanking(_) => AwsPersonalizeOperation::GetPersonalizedRanking,
        }
    }

    pub fn scope_digest(&self) -> &Digest {
        match self {
            Self::DescribeCampaign(request) => request.scope_digest(),
            Self::DescribeRecommender(request) => request.scope_digest(),
            Self::GetRecommendations(request) => request.scope_digest(),
            Self::GetPersonalizedRanking(request) => request.scope_digest(),
        }
    }

    pub fn request_digest(&self) -> &Digest {
        match self {
            Self::DescribeCampaign(request) => request.request_digest(),
            Self::DescribeRecommender(request) => request.request_digest(),
            Self::GetRecommendations(request) => request.request_digest(),
            Self::GetPersonalizedRanking(request) => request.request_digest(),
        }
    }

    pub fn path_and_query(&self) -> String {
        match self {
            Self::DescribeCampaign(request) => request.path_and_query(),
            Self::DescribeRecommender(request) => request.path_and_query(),
            Self::GetRecommendations(request) => request.path_and_query(),
            Self::GetPersonalizedRanking(request) => request.path_and_query(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailureEvidence {
    pub category: String,
    pub status_code: Option<u16>,
    pub failure_digest: Digest,
}

impl FailureEvidence {
    fn from_transport(error: &AwsPersonalizeTransportError) -> Self {
        let category = match error {
            AwsPersonalizeTransportError::BlockedEnv => "blocked_env",
            AwsPersonalizeTransportError::BadRequest => "bad_request",
            AwsPersonalizeTransportError::Unauthorized => "unauthorized",
            AwsPersonalizeTransportError::Forbidden => "forbidden",
            AwsPersonalizeTransportError::NotFound => "not_found",
            AwsPersonalizeTransportError::RateLimited { .. } => "rate_limited",
            AwsPersonalizeTransportError::ServerError { .. } => "server_error",
            AwsPersonalizeTransportError::Timeout => "timeout",
            AwsPersonalizeTransportError::AccessLost => "access_lost",
            AwsPersonalizeTransportError::Partial => "partial",
            AwsPersonalizeTransportError::InvalidResponse => "invalid_response",
        };
        Self {
            category: category.to_owned(),
            status_code: error.status_code(),
            failure_digest: Digest::from_parts(
                "aws-personalize-failure/v1",
                &[
                    ("category", category.to_owned()),
                    (
                        "status",
                        error
                            .status_code()
                            .map_or_else(String::new, |code| code.to_string()),
                    ),
                ],
            ),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsPersonalizeRecommendationProposal {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub operation: AwsPersonalizeOperation,
    pub request: AwsPersonalizeRecommendationRequest,
    pub mission: MissionProjection,
    pub project: ProjectProjection,
    pub work_product: WorkProductProjection,
    pub version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub evidence_policy_digest: Digest,
    pub registration_digest: Digest,
    pub campaign_metadata: Option<CampaignMetadata>,
    pub recommender_metadata: Option<RecommenderMetadata>,
    pub recommendation_result: Option<RecommendationResult>,
    pub state: RecommendationEvidenceState,
    pub failure: Option<FailureEvidence>,
    pub evidence: EvidenceDigests,
    pub provenance: TransportProvenance,
    pub proposal_digest: Digest,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

impl AwsPersonalizeRecommendationProposal {
    #[allow(clippy::too_many_arguments)]
    fn new(
        request: AwsPersonalizeRecommendationRequest,
        scope: &AwsPersonalizeRecommendationScope,
        registration: &AwsPersonalizeRecommendationRegistration,
        campaign_metadata: Option<CampaignMetadata>,
        recommender_metadata: Option<RecommenderMetadata>,
        recommendation_result: Option<RecommendationResult>,
        state: RecommendationEvidenceState,
        failure: Option<FailureEvidence>,
        evidence: EvidenceDigests,
        provenance: TransportProvenance,
    ) -> Self {
        let mut proposal = Self {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            operation: request.operation(),
            request,
            mission: MissionProjection::from(scope.mission()),
            project: ProjectProjection::from(scope.project()),
            work_product: WorkProductProjection::from(scope.work_product()),
            version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_digest: Digest::from_text(CONTRACT_DIGEST),
            provider_digest: registration.provider_digest.clone(),
            permission_digest: registration.permission_digest(),
            scope_digest: scope.digest(),
            evidence_policy_digest: evidence_policy_digest(),
            registration_digest: registration.registration_digest().clone(),
            campaign_metadata,
            recommender_metadata,
            recommendation_result,
            state,
            failure,
            evidence,
            provenance,
            proposal_digest: Digest::from_text("unsealed-aws-personalize-proposal"),
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
        };
        proposal.proposal_digest = proposal.calculate_proposal_digest();
        proposal
    }

    pub fn is_review_only(&self) -> bool {
        self.review_only
    }

    pub fn can_be_adopted(&self) -> bool {
        false
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.evidence.validate()?;
        if self.proposal_digest != self.calculate_proposal_digest()
            || self.service_id != SERVICE_ID
            || self.provider_id != PROVIDER_ID
            || self.consumer_id != CONSUMER_ID
            || self.operation != self.request.operation()
            || self.version_digest != Digest::from_text(PLUGIN_VERSION)
            || self.contract_digest != Digest::from_text(CONTRACT_DIGEST)
            || self.evidence_policy_digest != evidence_policy_digest()
            || !self.review_only
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
        {
            return Err(AwsPersonalizeRecommendationError::TamperedEvidence);
        }
        if self.request.scope_digest() != &self.scope_digest
            || self.evidence.request_digest != *self.request.request_digest()
        {
            return Err(AwsPersonalizeRecommendationError::ScopeMismatch);
        }
        if let Some(metadata) = &self.campaign_metadata {
            metadata.model_revision.validate()?;
            metadata.validate_digest()?;
        }
        if let Some(metadata) = &self.recommender_metadata {
            metadata.model_revision.validate()?;
            metadata.validate_digest()?;
        }
        if let Some(result) = &self.recommendation_result {
            result.validate()?;
        }
        Ok(())
    }

    fn calculate_proposal_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-personalize-recommendation-proposal/v1",
            &[
                ("service", self.service_id.clone()),
                ("provider", self.provider_id.clone()),
                ("consumer", self.consumer_id.clone()),
                ("operation", self.operation.as_str().to_owned()),
                ("request", self.request.request_digest().as_str().to_owned()),
                ("mission", self.mission.id_digest.as_str().to_owned()),
                ("mission_revision", self.mission.revision.to_string()),
                ("project", self.project.id_digest.as_str().to_owned()),
                ("project_revision", self.project.revision.to_string()),
                (
                    "work_product",
                    self.work_product.id_digest.as_str().to_owned(),
                ),
                (
                    "work_product_revision",
                    self.work_product.revision.to_string(),
                ),
                ("version", self.version_digest.as_str().to_owned()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider_digest", self.provider_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "evidence_policy",
                    self.evidence_policy_digest.as_str().to_owned(),
                ),
                ("registration", self.registration_digest.as_str().to_owned()),
                (
                    "campaign_metadata",
                    self.campaign_metadata
                        .as_ref()
                        .map_or_else(String::new, |value| {
                            value.metadata_digest.as_str().to_owned()
                        }),
                ),
                (
                    "recommender_metadata",
                    self.recommender_metadata
                        .as_ref()
                        .map_or_else(String::new, |value| {
                            value.metadata_digest.as_str().to_owned()
                        }),
                ),
                (
                    "result",
                    self.recommendation_result
                        .as_ref()
                        .map_or_else(String::new, |value| value.result_digest.as_str().to_owned()),
                ),
                ("state", format!("{:?}", self.state)),
                (
                    "failure",
                    self.failure.as_ref().map_or_else(String::new, |value| {
                        value.failure_digest.as_str().to_owned()
                    }),
                ),
                (
                    "evidence",
                    self.evidence.evidence_digest.as_str().to_owned(),
                ),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationFailure {
    pub code: String,
    pub detail_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub valid: bool,
    pub review_eligible: bool,
    pub proposal_digest: Digest,
    pub failures: Vec<VerificationFailure>,
    pub verification_digest: Digest,
}

impl VerificationReport {
    fn new(
        proposal: &AwsPersonalizeRecommendationProposal,
        failures: Vec<VerificationFailure>,
    ) -> Self {
        let valid = failures.is_empty();
        let review_eligible = valid
            && !matches!(
                proposal.state,
                RecommendationEvidenceState::Tampered | RecommendationEvidenceState::Revoked
            );
        let verification_digest = Digest::from_parts(
            "aws-personalize-verification-report/v1",
            &[
                ("proposal", proposal.proposal_digest.as_str().to_owned()),
                ("valid", valid.to_string()),
                (
                    "failures",
                    failures
                        .iter()
                        .map(|failure| failure.detail_digest.as_str())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
            ],
        );
        Self {
            valid,
            review_eligible,
            proposal_digest: proposal.proposal_digest.clone(),
            failures,
            verification_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityDescription {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub contract_version: String,
    pub provider_api_revision: String,
    pub operations: Vec<String>,
    pub max_results: u16,
    pub max_response_bytes: u64,
    pub read_only: bool,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub external_writes: bool,
}

pub struct AwsPersonalizeRecommendationService<T>
where
    T: AwsPersonalizeTransport,
{
    scope: AwsPersonalizeRecommendationScope,
    provider: AwsPersonalizeProvider<T>,
    registration: AwsPersonalizeRecommendationRegistration,
    now: DateTime<Utc>,
}

pub type AwsPersonalizeService<T> = AwsPersonalizeRecommendationService<T>;

impl<T> fmt::Debug for AwsPersonalizeRecommendationService<T>
where
    T: AwsPersonalizeTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsPersonalizeRecommendationService")
            .field("scope", &self.scope)
            .field("provider", &self.provider.definition())
            .field("registration", &self.registration)
            .field("now", &self.now)
            .finish()
    }
}

impl<T> AwsPersonalizeRecommendationService<T>
where
    T: AwsPersonalizeTransport,
{
    pub fn new(
        scope: AwsPersonalizeRecommendationScope,
        secret_reference: SecretReference,
        consent: crate::model::ConsentScope,
        provider: AwsPersonalizeProvider<T>,
        now: DateTime<Utc>,
    ) -> Result<Self> {
        let permission_snapshot = PermissionSnapshot::for_layer_one(1);
        let registration = AwsPersonalizeRecommendationRegistration::new(
            "aws-personalize-recommendation-registration",
            scope.clone(),
            secret_reference,
            permission_snapshot,
            consent,
            provider.definition(),
            1,
        )?;
        Self::with_registration(scope, provider, registration, now)
    }

    pub fn with_registration(
        scope: AwsPersonalizeRecommendationScope,
        provider: AwsPersonalizeProvider<T>,
        registration: AwsPersonalizeRecommendationRegistration,
        now: DateTime<Utc>,
    ) -> Result<Self> {
        registration.validate()?;
        if registration.scope_digest() != &scope.digest() {
            return Err(AwsPersonalizeRecommendationError::ScopeMismatch);
        }
        provider.definition().validate()?;
        Ok(Self {
            scope,
            provider,
            registration,
            now,
        })
    }

    pub fn scope(&self) -> &AwsPersonalizeRecommendationScope {
        &self.scope
    }

    pub fn provider(&self) -> &AwsPersonalizeProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsPersonalizeProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &AwsPersonalizeRecommendationRegistration {
        &self.registration
    }

    pub fn service_definition(&self) -> ServiceDefinition {
        ServiceDefinition::new()
    }

    pub fn describe_capabilities(&self) -> CapabilityDescription {
        CapabilityDescription {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            provider_api_revision: PROVIDER_API_REVISION.to_owned(),
            operations: [
                AwsPersonalizeOperation::DescribeCampaign,
                AwsPersonalizeOperation::DescribeRecommender,
                AwsPersonalizeOperation::GetRecommendations,
                AwsPersonalizeOperation::GetPersonalizedRanking,
            ]
            .into_iter()
            .map(|operation| operation.as_str().to_owned())
            .collect(),
            max_results: MAX_RESULTS,
            max_response_bytes: crate::MAX_RESPONSE_BYTES,
            read_only: true,
            proposal_only: true,
            connected: false,
            native: false,
            first_party: false,
            external_writes: false,
        }
    }

    pub fn register(&self) -> Result<&AwsPersonalizeRecommendationRegistration> {
        self.registration.validate()?;
        Ok(&self.registration)
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

    pub fn describe_campaign_request(&self) -> Result<AwsPersonalizeRecommendationRequest> {
        Ok(AwsPersonalizeRecommendationRequest::DescribeCampaign(
            DescribeCampaignRequest::for_scope(&self.scope)?,
        ))
    }

    pub fn describe_recommender_request(&self) -> Result<AwsPersonalizeRecommendationRequest> {
        Ok(AwsPersonalizeRecommendationRequest::DescribeRecommender(
            DescribeRecommenderRequest::for_scope(&self.scope)?,
        ))
    }

    pub fn recommendations_request(
        &self,
        num_results: u16,
    ) -> Result<AwsPersonalizeRecommendationRequest> {
        Ok(AwsPersonalizeRecommendationRequest::GetRecommendations(
            GetRecommendationsRequest::for_scope(&self.scope, num_results)?,
        ))
    }

    pub fn personalized_ranking_request(
        &self,
        num_results: u16,
    ) -> Result<AwsPersonalizeRecommendationRequest> {
        Ok(AwsPersonalizeRecommendationRequest::GetPersonalizedRanking(
            GetPersonalizedRankingRequest::for_scope(&self.scope, num_results)?,
        ))
    }

    pub fn default_request(&self) -> Result<AwsPersonalizeRecommendationRequest> {
        self.recommendations_request(3)
    }

    pub fn propose(
        &mut self,
        request: AwsPersonalizeRecommendationRequest,
    ) -> Result<AwsPersonalizeRecommendationProposal> {
        self.ensure_active()?;
        if request.scope_digest() != &self.scope.digest() {
            return Err(AwsPersonalizeRecommendationError::ScopeMismatch);
        }
        match request {
            AwsPersonalizeRecommendationRequest::DescribeCampaign(request) => {
                self.propose_campaign(request)
            }
            AwsPersonalizeRecommendationRequest::DescribeRecommender(request) => {
                self.propose_recommender(request)
            }
            AwsPersonalizeRecommendationRequest::GetRecommendations(request) => {
                self.propose_recommendations(request)
            }
            AwsPersonalizeRecommendationRequest::GetPersonalizedRanking(request) => {
                self.propose_personalized_ranking(request)
            }
        }
    }

    pub fn verify(&self, proposal: &AwsPersonalizeRecommendationProposal) -> VerificationReport {
        let mut failures = Vec::new();
        if let Err(error) = proposal.validate_integrity() {
            failures.push(failure("proposal_integrity", error));
        }
        if proposal.scope_digest != self.scope.digest()
            || proposal.mission.id_digest != self.scope.mission().digest()
            || proposal.mission.revision != self.scope.mission().revision()
            || proposal.project.id_digest != self.scope.project().digest()
            || proposal.project.revision != self.scope.project().revision()
            || proposal.work_product.id_digest != self.scope.work_product().digest()
            || proposal.work_product.revision != self.scope.work_product().revision()
        {
            failures.push(failure(
                "scope_mismatch",
                AwsPersonalizeRecommendationError::ScopeMismatch,
            ));
        }
        if proposal.registration_digest != *self.registration.registration_digest() {
            failures.push(failure(
                "registration_drift",
                AwsPersonalizeRecommendationError::InvalidRegistration,
            ));
        }
        if !self.registration.is_active() {
            failures.push(failure(
                "registration_revoked",
                AwsPersonalizeRecommendationError::RegistrationInactive,
            ));
        }
        if !self.registration.consent().is_active_at(self.now) {
            failures.push(failure(
                "consent_expired_or_revoked",
                AwsPersonalizeRecommendationError::ConsentExpired,
            ));
        }
        if proposal.provider_digest != *self.registration.provider_digest()
            || proposal.permission_digest != self.registration.permission_digest()
            || proposal.evidence_policy_digest != *self.registration.evidence_policy_digest()
        {
            failures.push(failure(
                "digest_drift",
                AwsPersonalizeRecommendationError::TamperedEvidence,
            ));
        }
        if matches!(
            proposal.state,
            RecommendationEvidenceState::Tampered | RecommendationEvidenceState::Revoked
        ) {
            failures.push(failure(
                "non_reviewable_state",
                AwsPersonalizeRecommendationError::TamperedEvidence,
            ));
        }
        VerificationReport::new(proposal, failures)
    }

    pub fn consumer(&self) -> Result<MissionAwsPersonalizeConsumer> {
        MissionAwsPersonalizeConsumer::new(self.scope.clone(), self.registration.clone())
    }

    fn ensure_active(&self) -> Result<()> {
        self.registration.validate()?;
        if !self.registration.is_active() {
            return Err(AwsPersonalizeRecommendationError::RegistrationInactive);
        }
        if self.registration.consent().is_revoked() {
            return Err(AwsPersonalizeRecommendationError::ConsentRevoked);
        }
        if !self.registration.consent().is_active_at(self.now) {
            return Err(AwsPersonalizeRecommendationError::ConsentExpired);
        }
        Ok(())
    }

    fn propose_campaign(
        &mut self,
        request: DescribeCampaignRequest,
    ) -> Result<AwsPersonalizeRecommendationProposal> {
        let request_digest = request.request_digest().clone();
        match self.provider.describe_campaign(&request) {
            Ok(response) => {
                response.metadata.validate_against(&self.scope)?;
                let evidence = EvidenceDigests::new(
                    request_digest,
                    Some(response.metadata.metadata_digest.clone()),
                    None,
                    None,
                    vec![response.response_digest.clone()],
                )?;
                Ok(AwsPersonalizeRecommendationProposal::new(
                    AwsPersonalizeRecommendationRequest::DescribeCampaign(request),
                    &self.scope,
                    &self.registration,
                    Some(response.metadata.clone()),
                    None,
                    None,
                    response.metadata.status.state(),
                    None,
                    evidence,
                    response.provenance,
                ))
            }
            Err(error) => Ok(self.failed_proposal(
                AwsPersonalizeRecommendationRequest::DescribeCampaign(request),
                state_for_transport(&error),
                error,
            )?),
        }
    }

    fn propose_recommender(
        &mut self,
        request: DescribeRecommenderRequest,
    ) -> Result<AwsPersonalizeRecommendationProposal> {
        let request_digest = request.request_digest().clone();
        match self.provider.describe_recommender(&request) {
            Ok(response) => {
                response.metadata.validate_against(&self.scope)?;
                let evidence = EvidenceDigests::new(
                    request_digest,
                    None,
                    Some(response.metadata.metadata_digest.clone()),
                    None,
                    vec![response.response_digest.clone()],
                )?;
                Ok(AwsPersonalizeRecommendationProposal::new(
                    AwsPersonalizeRecommendationRequest::DescribeRecommender(request),
                    &self.scope,
                    &self.registration,
                    None,
                    Some(response.metadata.clone()),
                    None,
                    response.metadata.status.state(),
                    None,
                    evidence,
                    response.provenance,
                ))
            }
            Err(error) => Ok(self.failed_proposal(
                AwsPersonalizeRecommendationRequest::DescribeRecommender(request),
                state_for_transport(&error),
                error,
            )?),
        }
    }

    fn propose_recommendations(
        &mut self,
        request: GetRecommendationsRequest,
    ) -> Result<AwsPersonalizeRecommendationProposal> {
        let generic = AwsPersonalizeRecommendationRequest::GetRecommendations(request.clone());
        match request.target() {
            ServingTarget::Campaign => {
                let describe = DescribeCampaignRequest::for_scope(&self.scope)?;
                let response = match self.provider.describe_campaign(&describe) {
                    Ok(response) => response,
                    Err(error) => {
                        return self.failed_proposal(generic, state_for_transport(&error), error);
                    }
                };
                response.metadata.validate_against(&self.scope)?;
                match self.provider.get_recommendations(&request) {
                    Ok(result) => {
                        let state = combine_metadata_state(response.metadata.status.state());
                        let evidence = EvidenceDigests::new(
                            request.request_digest().clone(),
                            Some(response.metadata.metadata_digest.clone()),
                            None,
                            Some(result.result.result_digest.clone()),
                            vec![
                                response.response_digest.clone(),
                                result.response_digest.clone(),
                            ],
                        )?;
                        Ok(AwsPersonalizeRecommendationProposal::new(
                            generic,
                            &self.scope,
                            &self.registration,
                            Some(response.metadata),
                            None,
                            Some(result.result),
                            state,
                            None,
                            evidence,
                            result.provenance,
                        ))
                    }
                    Err(error) => Ok(self.failed_with_metadata(
                        generic,
                        Some(response.metadata),
                        None,
                        state_for_transport(&error),
                        error,
                        request.request_digest().clone(),
                        vec![response.response_digest],
                    )?),
                }
            }
            ServingTarget::Recommender => {
                let describe = DescribeRecommenderRequest::for_scope(&self.scope)?;
                let response = match self.provider.describe_recommender(&describe) {
                    Ok(response) => response,
                    Err(error) => {
                        return self.failed_proposal(generic, state_for_transport(&error), error);
                    }
                };
                response.metadata.validate_against(&self.scope)?;
                match self.provider.get_recommendations(&request) {
                    Ok(result) => {
                        let state = combine_metadata_state(response.metadata.status.state());
                        let evidence = EvidenceDigests::new(
                            request.request_digest().clone(),
                            None,
                            Some(response.metadata.metadata_digest.clone()),
                            Some(result.result.result_digest.clone()),
                            vec![
                                response.response_digest.clone(),
                                result.response_digest.clone(),
                            ],
                        )?;
                        Ok(AwsPersonalizeRecommendationProposal::new(
                            generic,
                            &self.scope,
                            &self.registration,
                            None,
                            Some(response.metadata),
                            Some(result.result),
                            state,
                            None,
                            evidence,
                            result.provenance,
                        ))
                    }
                    Err(error) => Ok(self.failed_with_metadata(
                        generic,
                        None,
                        Some(response.metadata),
                        state_for_transport(&error),
                        error,
                        request.request_digest().clone(),
                        vec![response.response_digest],
                    )?),
                }
            }
        }
    }

    fn propose_personalized_ranking(
        &mut self,
        request: GetPersonalizedRankingRequest,
    ) -> Result<AwsPersonalizeRecommendationProposal> {
        let generic = AwsPersonalizeRecommendationRequest::GetPersonalizedRanking(request.clone());
        let describe = DescribeCampaignRequest::for_scope(&self.scope)?;
        let response = match self.provider.describe_campaign(&describe) {
            Ok(response) => response,
            Err(error) => {
                return self.failed_proposal(generic, state_for_transport(&error), error);
            }
        };
        response.metadata.validate_against(&self.scope)?;
        match self.provider.get_personalized_ranking(&request) {
            Ok(result) => {
                let state = combine_metadata_state(response.metadata.status.state());
                let evidence = EvidenceDigests::new(
                    request.request_digest().clone(),
                    Some(response.metadata.metadata_digest.clone()),
                    None,
                    Some(result.result.result_digest.clone()),
                    vec![
                        response.response_digest.clone(),
                        result.response_digest.clone(),
                    ],
                )?;
                Ok(AwsPersonalizeRecommendationProposal::new(
                    generic,
                    &self.scope,
                    &self.registration,
                    Some(response.metadata),
                    None,
                    Some(result.result),
                    state,
                    None,
                    evidence,
                    result.provenance,
                ))
            }
            Err(error) => Ok(self.failed_with_metadata(
                generic,
                Some(response.metadata),
                None,
                state_for_transport(&error),
                error,
                request.request_digest().clone(),
                vec![response.response_digest],
            )?),
        }
    }

    fn failed_proposal(
        &self,
        request: AwsPersonalizeRecommendationRequest,
        state: RecommendationEvidenceState,
        error: AwsPersonalizeTransportError,
    ) -> Result<AwsPersonalizeRecommendationProposal> {
        self.failed_with_metadata(
            request.clone(),
            None,
            None,
            state,
            error,
            request.request_digest().clone(),
            Vec::new(),
        )
    }

    fn failed_with_metadata(
        &self,
        request: AwsPersonalizeRecommendationRequest,
        campaign_metadata: Option<CampaignMetadata>,
        recommender_metadata: Option<RecommenderMetadata>,
        state: RecommendationEvidenceState,
        error: AwsPersonalizeTransportError,
        request_digest: Digest,
        response_digests: Vec<Digest>,
    ) -> Result<AwsPersonalizeRecommendationProposal> {
        let failure = FailureEvidence::from_transport(&error);
        let evidence = EvidenceDigests::new(
            request_digest,
            campaign_metadata
                .as_ref()
                .map(|value| value.metadata_digest.clone()),
            recommender_metadata
                .as_ref()
                .map(|value| value.metadata_digest.clone()),
            None,
            response_digests,
        )?;
        Ok(AwsPersonalizeRecommendationProposal::new(
            request,
            &self.scope,
            &self.registration,
            campaign_metadata,
            recommender_metadata,
            None,
            state,
            Some(failure),
            evidence,
            self.provider.provenance(),
        ))
    }
}

fn valid_registration_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= crate::MAX_IDENTIFIER_BYTES
        && value.trim() == value
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn state_for_transport(error: &AwsPersonalizeTransportError) -> RecommendationEvidenceState {
    match error {
        AwsPersonalizeTransportError::Unauthorized
        | AwsPersonalizeTransportError::Forbidden
        | AwsPersonalizeTransportError::AccessLost => RecommendationEvidenceState::AccessLost,
        AwsPersonalizeTransportError::Partial => RecommendationEvidenceState::Partial,
        AwsPersonalizeTransportError::InvalidResponse => RecommendationEvidenceState::Tampered,
        AwsPersonalizeTransportError::BadRequest
        | AwsPersonalizeTransportError::NotFound
        | AwsPersonalizeTransportError::RateLimited { .. }
        | AwsPersonalizeTransportError::ServerError { .. }
        | AwsPersonalizeTransportError::Timeout
        | AwsPersonalizeTransportError::BlockedEnv => RecommendationEvidenceState::ProviderUnknown,
    }
}

fn combine_metadata_state(state: RecommendationEvidenceState) -> RecommendationEvidenceState {
    state
}

fn failure(code: &str, error: AwsPersonalizeRecommendationError) -> VerificationFailure {
    VerificationFailure {
        code: code.to_owned(),
        detail_digest: Digest::from_parts(
            "aws-personalize-verification-failure/v1",
            &[("code", code.to_owned()), ("error", error.to_string())],
        ),
    }
}

#[allow(dead_code)]
fn _scope_permissions(scope: &AwsPersonalizeRecommendationScope) -> BTreeSet<String> {
    let _ = scope;
    crate::LAYER1_PERMISSIONS
        .iter()
        .map(|permission| (*permission).to_owned())
        .collect()
}
