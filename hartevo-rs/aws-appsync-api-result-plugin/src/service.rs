use std::{collections::HashSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::consumer::MissionAwsAppSyncConsumer;
use crate::error::{AwsAppSyncApiResultError, AwsAppSyncTransportError, Result};
use crate::model::{
    ApiMetadata, ApiSummary, AppSyncEvidenceState, AssociationPage, AssociationProjection,
    AwsAppSyncApiScope, ConsentScope, CostReceipt, CostSummary, DeploymentState, Digest,
    EvidenceDigests, MissionProjection, PermissionSnapshot, ProjectProjection, RequestReceipt,
    SchemaCreationStatus, SchemaDeploymentMetadata, SecretReference, TransportProvenance,
    WorkProductProjection, mission_projection, project_projection, validate_cursor_seen,
    work_product_projection,
};
use crate::provider::{
    AwsAppSyncOperation, AwsAppSyncProvider, AwsAppSyncProviderDefinition, AwsAppSyncTransport,
    GetApiRequest, GetSchemaCreationStatusRequest, ListDataSourcesRequest, ListGraphqlApisRequest,
    ListResolversRequest,
};
use crate::{
    API_REVISION, CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_VERSION, MAX_PAGES, MAX_STALENESS_SECONDS,
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
            "aws-appsync-registration-transition/v1",
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
pub struct AwsAppSyncApiResultRegistration {
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
    scope: AwsAppSyncApiScope,
    scope_digest: Digest,
    secret_reference: SecretReference,
    registration_revision: u64,
    evidence_digest: Digest,
    status: RegistrationStatus,
    registration_digest: Digest,
}

impl AwsAppSyncApiResultRegistration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        scope: AwsAppSyncApiScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        consent: ConsentScope,
        provider: &AwsAppSyncProviderDefinition,
        registration_revision: u64,
    ) -> Result<Self> {
        let scope_digest = scope.digest();
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
            scope,
            scope_digest,
            secret_reference,
            registration_revision,
            evidence_digest: Digest::from_text("unsealed-aws-appsync-registration-evidence"),
            status: RegistrationStatus::Active,
            registration_digest: Digest::from_text("unsealed-aws-appsync-registration"),
        };
        registration.evidence_digest = registration.calculate_evidence_digest();
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

    pub fn consent(&self) -> &ConsentScope {
        &self.consent
    }

    pub fn consent_digest(&self) -> Digest {
        self.consent.digest()
    }

    pub fn scope(&self) -> &AwsAppSyncApiScope {
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

    pub fn evidence_digest(&self) -> &Digest {
        &self.evidence_digest
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
            || !crate::valid_release(&self.provider_release)
            || self.api_digest != Digest::from_text(API_REVISION)
            || self.registration_revision == 0
            || self.scope_digest != self.scope.digest()
            || self.evidence_digest != self.calculate_evidence_digest()
            || self.registration_digest != self.calculate_registration_digest()
        {
            return Err(AwsAppSyncApiResultError::InvalidRegistration);
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
            return Err(AwsAppSyncApiResultError::InvalidConsent);
        }
        self.consent.validate()
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsAppSyncApiResultError::RegistrationReversed);
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

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsAppSyncApiResultError::RegistrationReversed);
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

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsAppSyncApiResultError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Active;
        self.registration_digest = self.calculate_registration_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    fn calculate_evidence_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-appsync-registration-evidence/v1",
            &[
                ("plugin", self.version_digest.as_str().to_owned()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("api", self.api_digest.as_str().to_owned()),
                ("permission", self.permission_digest().as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("secret", self.secret_reference_digest().as_str().to_owned()),
            ],
        )
    }

    fn calculate_registration_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-appsync-registration/v1",
            &[
                ("id", self.id.clone()),
                ("plugin", self.version_digest.as_str().to_owned()),
                ("contract", self.contract_digest.as_str().to_owned()),
                ("provider", self.provider_digest.as_str().to_owned()),
                ("api", self.api_digest.as_str().to_owned()),
                ("permission", self.permission_digest().as_str().to_owned()),
                ("consent", self.consent_digest().as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("secret", self.secret_reference_digest().as_str().to_owned()),
                ("evidence", self.evidence_digest.as_str().to_owned()),
                ("revision", self.registration_revision.to_string()),
                ("status", format!("{:?}", self.status)),
            ],
        )
    }
}

pub type AwsAppSyncRegistration = AwsAppSyncApiResultRegistration;

impl fmt::Debug for AwsAppSyncApiResultRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsAppSyncApiResultRegistration")
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
            .field("evidence_digest", &self.evidence_digest)
            .field("registration_revision", &self.registration_revision)
            .field("status", &self.status)
            .field("registration_digest", &self.registration_digest)
            .finish()
    }
}

impl Serialize for AwsAppSyncApiResultRegistration {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AwsAppSyncApiResultRegistration", 21)?;
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
        state.serialize_field("evidenceDigest", &self.evidence_digest)?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("reversible", &true)?;
        state.serialize_field("revocable", &true)?;
        state.serialize_field("registrationDigest", &self.registration_digest)?;
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
    pub arbitrary_graphql: bool,
    pub mutation_authority: bool,
    pub outcome_adoption: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppSyncEvidenceRequest {
    pub scope_digest: Digest,
    pub page_size: u16,
    pub max_pages: u16,
    pub expected_provider_digest: Digest,
    pub expected_registration_digest: Digest,
    pub observed_at: DateTime<Utc>,
}

impl AppSyncEvidenceRequest {
    pub fn new(
        scope: &AwsAppSyncApiScope,
        page_size: u16,
        max_pages: u16,
        expected_provider_digest: Digest,
        expected_registration_digest: Digest,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        crate::model::validate_page_size(page_size)?;
        if max_pages == 0 || max_pages > MAX_PAGES {
            return Err(AwsAppSyncApiResultError::InvalidRequest);
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
            "aws-appsync-evidence-request/v1",
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
    pub operation: AwsAppSyncOperation,
    pub status_code: Option<u16>,
    pub category: String,
    pub failure_digest: Digest,
}

impl FailureEvidence {
    fn from_transport(operation: AwsAppSyncOperation, error: &AwsAppSyncTransportError) -> Self {
        let category = match error {
            AwsAppSyncTransportError::BlockedEnv => "blocked_env",
            AwsAppSyncTransportError::BadRequest => "bad_request",
            AwsAppSyncTransportError::Unauthorized => "unauthorized",
            AwsAppSyncTransportError::Forbidden => "forbidden",
            AwsAppSyncTransportError::NotFound => "not_found",
            AwsAppSyncTransportError::Conflict => "conflict",
            AwsAppSyncTransportError::RateLimited { .. } => "throttled",
            AwsAppSyncTransportError::ServerError { .. } => "server_error",
            AwsAppSyncTransportError::Timeout => "timeout",
            AwsAppSyncTransportError::AccessLost => "access_loss",
            AwsAppSyncTransportError::Partial => "partial",
            AwsAppSyncTransportError::Unknown => "provider_unknown",
            AwsAppSyncTransportError::InvalidResponse => "invalid_response",
            AwsAppSyncTransportError::Tampered => "tampered",
            AwsAppSyncTransportError::ConfigDrift => "revision_drift",
            AwsAppSyncTransportError::PaginationLoop => "pagination_loop",
        }
        .to_owned();
        let failure_digest = Digest::from_parts(
            "aws-appsync-failure/v1",
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
pub struct AwsAppSyncApiResultProposal {
    pub service_id: String,
    pub consumer_id: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub account_digest: Digest,
    pub region_digest: Digest,
    pub api_digest: Digest,
    pub api_type: crate::model::AppSyncApiType,
    pub mission: MissionProjection,
    pub project: ProjectProjection,
    pub work_product: WorkProductProjection,
    pub state: AppSyncEvidenceState,
    pub list_pages: u16,
    pub list_complete: bool,
    pub data_source_pages: u16,
    pub resolver_pages: u16,
    pub associations_complete: bool,
    pub api: Option<ApiMetadata>,
    pub schema: Option<SchemaDeploymentMetadata>,
    pub associations: Option<AssociationProjection>,
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

impl AwsAppSyncApiResultProposal {
    #[allow(clippy::too_many_arguments)]
    fn new(
        registration: &AwsAppSyncApiResultRegistration,
        provider: &AwsAppSyncProviderDefinition,
        request: &AppSyncEvidenceRequest,
        state: AppSyncEvidenceState,
        list_pages: u16,
        list_complete: bool,
        data_source_pages: u16,
        resolver_pages: u16,
        associations_complete: bool,
        api: Option<ApiMetadata>,
        schema: Option<SchemaDeploymentMetadata>,
        associations: Option<AssociationProjection>,
        failure: Option<FailureEvidence>,
        request_receipts: Vec<RequestReceipt>,
        cost_receipts: Vec<CostReceipt>,
        provenance: TransportProvenance,
    ) -> Self {
        let mut evidence = EvidenceDigests {
            plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_digest: registration.contract_digest.clone(),
            provider_digest: provider.provider_digest.clone(),
            api_revision_digest: registration.api_digest.clone(),
            permission_digest: registration.permission_digest(),
            scope_digest: registration.scope_digest.clone(),
            api_digest: api.as_ref().map(|value| value.metadata_digest.clone()),
            schema_digest: schema.as_ref().map(|value| value.schema_digest.clone()),
            deployment_digest: schema
                .as_ref()
                .map(|value| value.deployment_revision_digest.clone()),
            association_digest: associations
                .as_ref()
                .map(|value| value.association_digest.clone()),
            evidence_digest: Digest::from_text("unsealed-aws-appsync-evidence"),
        };
        evidence.evidence_digest = calculate_evidence_digest(
            &evidence,
            &request.digest(),
            state,
            list_pages,
            list_complete,
            data_source_pages,
            resolver_pages,
            associations_complete,
            api.as_ref(),
            schema.as_ref(),
            associations.as_ref(),
            failure.as_ref(),
            &request_receipts,
            &cost_receipts,
        );
        let cost_summary = CostSummary::from_receipts(&cost_receipts);
        let mut proposal = Self {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            registration_digest: registration.registration_digest.clone(),
            scope_digest: registration.scope_digest.clone(),
            request_digest: request.digest(),
            account_digest: registration.scope().account().digest(),
            region_digest: registration.scope().region().digest(),
            api_digest: registration.scope().api().digest(),
            api_type: registration.scope().api_type(),
            mission: mission_projection(registration.scope().mission()),
            project: project_projection(registration.scope().project()),
            work_product: work_product_projection(registration.scope().work_product()),
            state,
            list_pages,
            list_complete,
            data_source_pages,
            resolver_pages,
            associations_complete,
            api,
            schema,
            associations,
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
            proposal_digest: Digest::from_text("unsealed-aws-appsync-proposal"),
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
            || self.proposal_digest != self.calculate_digest()
        {
            return Err(AwsAppSyncApiResultError::TamperedEvidence);
        }
        if let Some(api) = &self.api {
            if api.api_identity_digest != self.api_digest {
                return Err(AwsAppSyncApiResultError::TamperedEvidence);
            }
        }
        if let Some(schema) = &self.schema {
            schema.schema_digest.validate()?;
        }
        if let Some(associations) = &self.associations {
            associations.data_source_digest.validate()?;
            associations.resolver_digest.validate()?;
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
            "aws-appsync-api-result-proposal/v1",
            &[
                ("service", self.service_id.clone()),
                ("consumer", self.consumer_id.clone()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("account", self.account_digest.as_str().to_owned()),
                ("region", self.region_digest.as_str().to_owned()),
                ("api", self.api_digest.as_str().to_owned()),
                ("api_type", self.api_type.as_str().to_owned()),
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
                ("state", self.state.as_str().to_owned()),
                ("list_pages", self.list_pages.to_string()),
                ("list_complete", self.list_complete.to_string()),
                ("data_source_pages", self.data_source_pages.to_string()),
                ("resolver_pages", self.resolver_pages.to_string()),
                (
                    "associations_complete",
                    self.associations_complete.to_string(),
                ),
                (
                    "api_projection",
                    self.api.as_ref().map_or_else(String::new, |value| {
                        serde_json::to_string(value).expect("api serializes")
                    }),
                ),
                (
                    "schema_projection",
                    self.schema.as_ref().map_or_else(String::new, |value| {
                        serde_json::to_string(value).expect("schema serializes")
                    }),
                ),
                (
                    "association_projection",
                    self.associations
                        .as_ref()
                        .map_or_else(String::new, |value| {
                            serde_json::to_string(value).expect("associations serialize")
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

#[allow(clippy::too_many_arguments)]
fn calculate_evidence_digest(
    evidence: &EvidenceDigests,
    request_digest: &Digest,
    state: AppSyncEvidenceState,
    list_pages: u16,
    list_complete: bool,
    data_source_pages: u16,
    resolver_pages: u16,
    associations_complete: bool,
    api: Option<&ApiMetadata>,
    schema: Option<&SchemaDeploymentMetadata>,
    associations: Option<&AssociationProjection>,
    failure: Option<&FailureEvidence>,
    request_receipts: &[RequestReceipt],
    cost_receipts: &[CostReceipt],
) -> Digest {
    Digest::from_parts(
        "aws-appsync-evidence/v1",
        &[
            ("plugin", evidence.plugin_version_digest.as_str().to_owned()),
            ("contract", evidence.contract_digest.as_str().to_owned()),
            ("provider", evidence.provider_digest.as_str().to_owned()),
            (
                "api_revision",
                evidence.api_revision_digest.as_str().to_owned(),
            ),
            ("permission", evidence.permission_digest.as_str().to_owned()),
            ("scope", evidence.scope_digest.as_str().to_owned()),
            (
                "api",
                evidence
                    .api_digest
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
            ),
            (
                "schema",
                evidence
                    .schema_digest
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
            ),
            (
                "deployment",
                evidence
                    .deployment_digest
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
            ),
            (
                "associations",
                evidence
                    .association_digest
                    .as_ref()
                    .map_or_else(String::new, |value| value.as_str().to_owned()),
            ),
            ("request", request_digest.as_str().to_owned()),
            ("state", state.as_str().to_owned()),
            ("list_pages", list_pages.to_string()),
            ("list_complete", list_complete.to_string()),
            ("data_source_pages", data_source_pages.to_string()),
            ("resolver_pages", resolver_pages.to_string()),
            ("associations_complete", associations_complete.to_string()),
            (
                "api_projection",
                api.map_or_else(String::new, |value| {
                    value.metadata_digest.as_str().to_owned()
                }),
            ),
            (
                "schema_projection",
                schema.map_or_else(String::new, |value| {
                    value.metadata_digest.as_str().to_owned()
                }),
            ),
            (
                "association_projection",
                associations.map_or_else(String::new, |value| {
                    value.association_digest.as_str().to_owned()
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

pub struct AwsAppSyncApiResultService<T: AwsAppSyncTransport> {
    registration: AwsAppSyncApiResultRegistration,
    provider: AwsAppSyncProvider<T>,
}

impl<T: AwsAppSyncTransport> fmt::Debug for AwsAppSyncApiResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsAppSyncApiResultService")
            .field("registration", &self.registration)
            .field("provider", &self.provider)
            .finish()
    }
}

impl<T: AwsAppSyncTransport> AwsAppSyncApiResultService<T> {
    pub fn new(
        scope: AwsAppSyncApiScope,
        secret_reference: SecretReference,
        consent: ConsentScope,
        provider: AwsAppSyncProvider<T>,
        _observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        let registration = AwsAppSyncApiResultRegistration::new(
            "aws-appsync-api-result-registration",
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
        registration: AwsAppSyncApiResultRegistration,
        provider: AwsAppSyncProvider<T>,
    ) -> Result<Self> {
        registration.validate()?;
        if registration.provider_digest() != &provider.definition().provider_digest {
            return Err(AwsAppSyncApiResultError::ProviderDrift);
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
            operations: [
                AwsAppSyncOperation::ListGraphqlApis,
                AwsAppSyncOperation::GetApi,
                AwsAppSyncOperation::GetSchemaCreationStatus,
                AwsAppSyncOperation::ListDataSources,
                AwsAppSyncOperation::ListResolvers,
            ]
            .into_iter()
            .map(AwsAppSyncOperation::as_str)
            .map(str::to_owned)
            .collect(),
            permissions: crate::LAYER1_PERMISSIONS
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            read_only: true,
            proposal_only: true,
            connected: false,
            native: false,
            first_party: false,
            arbitrary_graphql: false,
            mutation_authority: false,
            outcome_adoption: false,
        }
    }

    pub fn scope(&self) -> &AwsAppSyncApiScope {
        self.registration.scope()
    }

    pub fn registration(&self) -> &AwsAppSyncApiResultRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut AwsAppSyncApiResultRegistration {
        &mut self.registration
    }

    pub fn provider(&self) -> &AwsAppSyncProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsAppSyncProvider<T> {
        &mut self.provider
    }

    pub fn default_request(&self, observed_at: DateTime<Utc>) -> Result<AppSyncEvidenceRequest> {
        self.request(crate::MAX_PAGE_SIZE, MAX_PAGES, observed_at)
    }

    pub fn request(
        &self,
        page_size: u16,
        max_pages: u16,
        observed_at: DateTime<Utc>,
    ) -> Result<AppSyncEvidenceRequest> {
        AppSyncEvidenceRequest::new(
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

    pub fn consumer(&self) -> Result<MissionAwsAppSyncConsumer> {
        MissionAwsAppSyncConsumer::new(self.scope().clone(), self.registration.clone())
            .map_err(|_| AwsAppSyncApiResultError::InvalidRegistration)
    }

    pub fn verify(&self, proposal: &AwsAppSyncApiResultProposal) -> VerificationReport {
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
        if proposal.evidence.api_revision_digest != *self.registration.api_digest() {
            failures.push(VerificationFailure::ApiRevisionDigestMismatch);
        }
        if proposal.validate_integrity().is_err() {
            failures.push(VerificationFailure::TamperedEvidence);
        }
        match proposal.state {
            AppSyncEvidenceState::AccessLost => failures.push(VerificationFailure::AccessLoss),
            AppSyncEvidenceState::Partial => failures.push(VerificationFailure::PartialEvidence),
            AppSyncEvidenceState::Stale => failures.push(VerificationFailure::RevisionDrift),
            AppSyncEvidenceState::Tampered => failures.push(VerificationFailure::TamperedEvidence),
            AppSyncEvidenceState::ProviderUnknown => {
                failures.push(VerificationFailure::ProviderUnknown);
            }
            AppSyncEvidenceState::Revoked => {
                failures.push(VerificationFailure::RegistrationInactive);
            }
            AppSyncEvidenceState::Available
            | AppSyncEvidenceState::Disabled
            | AppSyncEvidenceState::Degraded => {}
        }
        failures.sort_unstable();
        failures.dedup();
        let valid = failures.is_empty();
        let review_eligible = valid
            && proposal.list_complete
            && proposal.associations_complete
            && proposal.api.is_some()
            && proposal.schema.is_some()
            && proposal.associations.is_some()
            && proposal.state.is_review_complete()
            && !proposal.connected
            && !proposal.native
            && !proposal.first_party
            && !proposal.provider_receipt;
        VerificationReport::new(valid, review_eligible, failures)
    }

    pub fn propose(
        &mut self,
        request: AppSyncEvidenceRequest,
    ) -> Result<AwsAppSyncApiResultProposal> {
        self.validate_request(&request)?;
        if !self.registration.is_active() {
            return Ok(self.failed_proposal(
                &request,
                AppSyncEvidenceState::Revoked,
                0,
                false,
                0,
                0,
                false,
                None,
                None,
                None,
                Some(FailureEvidence::from_transport(
                    AwsAppSyncOperation::ListGraphqlApis,
                    &AwsAppSyncTransportError::Unknown,
                )),
                Vec::new(),
                Vec::new(),
            ));
        }

        let mut list_request = ListGraphqlApisRequest::first(self.scope(), request.page_size)?;
        let mut seen_cursors = HashSet::new();
        let mut request_receipts = Vec::new();
        let mut cost_receipts = Vec::new();
        let mut list_pages = 1;
        let mut selected_summary: Option<ApiSummary> = None;

        loop {
            match self.provider.list_graphql_apis(&list_request) {
                Ok(response) => {
                    request_receipts.push(response.request_receipt.clone());
                    cost_receipts.push(response.cost_receipt.clone());
                    for api in response.apis {
                        if api.api_identity_digest == self.scope().api().digest() {
                            if selected_summary.replace(api).is_some() {
                                return Ok(self.failed_proposal(
                                    &request,
                                    AppSyncEvidenceState::Stale,
                                    list_pages,
                                    false,
                                    0,
                                    0,
                                    false,
                                    None,
                                    None,
                                    None,
                                    Some(FailureEvidence::from_transport(
                                        AwsAppSyncOperation::ListGraphqlApis,
                                        &AwsAppSyncTransportError::ConfigDrift,
                                    )),
                                    request_receipts,
                                    cost_receipts,
                                ));
                            }
                        }
                    }
                    if let Some(cursor) = response.next_cursor {
                        if validate_cursor_seen(&mut seen_cursors, cursor.marker_digest()).is_err()
                        {
                            return Ok(self.failed_proposal(
                                &request,
                                AppSyncEvidenceState::Tampered,
                                list_pages,
                                false,
                                0,
                                0,
                                false,
                                None,
                                None,
                                None,
                                Some(FailureEvidence::from_transport(
                                    AwsAppSyncOperation::ListGraphqlApis,
                                    &AwsAppSyncTransportError::PaginationLoop,
                                )),
                                request_receipts,
                                cost_receipts,
                            ));
                        }
                        if list_pages >= request.max_pages {
                            return Ok(self.failed_proposal(
                                &request,
                                AppSyncEvidenceState::Partial,
                                list_pages,
                                false,
                                0,
                                0,
                                false,
                                None,
                                None,
                                None,
                                Some(FailureEvidence::from_transport(
                                    AwsAppSyncOperation::ListGraphqlApis,
                                    &AwsAppSyncTransportError::Partial,
                                )),
                                request_receipts,
                                cost_receipts,
                            ));
                        }
                        list_request = ListGraphqlApisRequest::new(
                            self.scope(),
                            request.page_size,
                            Some(cursor),
                        )?;
                        list_pages = list_request.page_number();
                    } else {
                        break;
                    }
                }
                Err(error) => {
                    request_receipts.push(list_request.recorded_request().receipt());
                    cost_receipts.push(CostReceipt::new(
                        AwsAppSyncOperation::ListGraphqlApis.as_str(),
                        0,
                    )?);
                    return Ok(self.failed_proposal(
                        &request,
                        state_for_transport(&error),
                        list_pages,
                        false,
                        0,
                        0,
                        false,
                        None,
                        None,
                        None,
                        Some(FailureEvidence::from_transport(
                            AwsAppSyncOperation::ListGraphqlApis,
                            &error,
                        )),
                        request_receipts,
                        cost_receipts,
                    ));
                }
            }
        }

        let list_complete = true;
        let Some(summary) = selected_summary else {
            return Ok(self.failed_proposal(
                &request,
                AppSyncEvidenceState::ProviderUnknown,
                list_pages,
                list_complete,
                0,
                0,
                false,
                None,
                None,
                None,
                Some(FailureEvidence::from_transport(
                    AwsAppSyncOperation::ListGraphqlApis,
                    &AwsAppSyncTransportError::NotFound,
                )),
                request_receipts,
                cost_receipts,
            ));
        };

        let get_request = GetApiRequest::for_scope(self.scope())?;
        let api_response = match self.provider.get_api(&get_request) {
            Ok(response) => response,
            Err(error) => {
                request_receipts.push(get_request.recorded_request().receipt());
                cost_receipts.push(CostReceipt::new(AwsAppSyncOperation::GetApi.as_str(), 0)?);
                return Ok(self.failed_proposal(
                    &request,
                    state_for_transport(&error),
                    list_pages,
                    list_complete,
                    0,
                    0,
                    false,
                    None,
                    None,
                    None,
                    Some(FailureEvidence::from_transport(
                        AwsAppSyncOperation::GetApi,
                        &error,
                    )),
                    request_receipts,
                    cost_receipts,
                ));
            }
        };
        request_receipts.push(api_response.request_receipt.clone());
        cost_receipts.push(api_response.cost_receipt.clone());
        let api = api_response.api.clone();
        if summary.api_identity_digest != api.api_identity_digest
            || summary.api_type != api.api_type
        {
            return Ok(self.failed_proposal(
                &request,
                AppSyncEvidenceState::Stale,
                list_pages,
                list_complete,
                0,
                0,
                false,
                Some(api),
                None,
                None,
                Some(FailureEvidence::from_transport(
                    AwsAppSyncOperation::GetApi,
                    &AwsAppSyncTransportError::ConfigDrift,
                )),
                request_receipts,
                cost_receipts,
            ));
        }

        let schema_request = GetSchemaCreationStatusRequest::for_scope(self.scope())?;
        let schema_response = match self.provider.get_schema_creation_status(&schema_request) {
            Ok(response) => response,
            Err(error) => {
                request_receipts.push(schema_request.recorded_request().receipt());
                cost_receipts.push(CostReceipt::new(
                    AwsAppSyncOperation::GetSchemaCreationStatus.as_str(),
                    0,
                )?);
                return Ok(self.failed_proposal(
                    &request,
                    state_for_transport(&error),
                    list_pages,
                    list_complete,
                    0,
                    0,
                    false,
                    Some(api),
                    None,
                    None,
                    Some(FailureEvidence::from_transport(
                        AwsAppSyncOperation::GetSchemaCreationStatus,
                        &error,
                    )),
                    request_receipts,
                    cost_receipts,
                ));
            }
        };
        request_receipts.push(schema_response.request_receipt.clone());
        cost_receipts.push(schema_response.cost_receipt.clone());
        let schema = schema_response.schema.clone();

        let (data_pages, data_complete, data_failure) =
            self.collect_data_sources(&request, &mut request_receipts, &mut cost_receipts)?;
        if let Some(error) = data_failure {
            return Ok(self.failed_proposal(
                &request,
                state_for_transport(&error),
                list_pages,
                list_complete,
                data_pages.len() as u16,
                0,
                false,
                Some(api),
                Some(schema),
                None,
                Some(FailureEvidence::from_transport(
                    AwsAppSyncOperation::ListDataSources,
                    &error,
                )),
                request_receipts,
                cost_receipts,
            ));
        }

        let (resolver_pages, resolver_complete, resolver_failure) =
            self.collect_resolvers(&request, &mut request_receipts, &mut cost_receipts)?;
        if let Some(error) = resolver_failure {
            return Ok(self.failed_proposal(
                &request,
                state_for_transport(&error),
                list_pages,
                list_complete,
                data_pages.len() as u16,
                resolver_pages.len() as u16,
                false,
                Some(api),
                Some(schema),
                None,
                Some(FailureEvidence::from_transport(
                    AwsAppSyncOperation::ListResolvers,
                    &error,
                )),
                request_receipts,
                cost_receipts,
            ));
        }

        let associations_complete = data_complete && resolver_complete;
        if !associations_complete {
            return Ok(self.failed_proposal(
                &request,
                AppSyncEvidenceState::Partial,
                list_pages,
                list_complete,
                data_pages.len() as u16,
                resolver_pages.len() as u16,
                false,
                Some(api),
                Some(schema),
                None,
                Some(FailureEvidence::from_transport(
                    AwsAppSyncOperation::ListDataSources,
                    &AwsAppSyncTransportError::Partial,
                )),
                request_receipts,
                cost_receipts,
            ));
        }

        let associations = match AssociationProjection::from_pages(
            self.scope(),
            &data_pages,
            &resolver_pages,
            schema.deployment_revision_digest.as_str(),
        ) {
            Ok(value) => value,
            Err(AwsAppSyncApiResultError::RevisionDrift) => {
                return Ok(self.failed_proposal(
                    &request,
                    AppSyncEvidenceState::Stale,
                    list_pages,
                    list_complete,
                    data_pages.len() as u16,
                    resolver_pages.len() as u16,
                    true,
                    Some(api),
                    Some(schema),
                    None,
                    Some(FailureEvidence::from_transport(
                        AwsAppSyncOperation::ListResolvers,
                        &AwsAppSyncTransportError::ConfigDrift,
                    )),
                    request_receipts,
                    cost_receipts,
                ));
            }
            Err(_) => {
                return Ok(self.failed_proposal(
                    &request,
                    AppSyncEvidenceState::Tampered,
                    list_pages,
                    list_complete,
                    data_pages.len() as u16,
                    resolver_pages.len() as u16,
                    true,
                    Some(api),
                    Some(schema),
                    None,
                    Some(FailureEvidence::from_transport(
                        AwsAppSyncOperation::ListResolvers,
                        &AwsAppSyncTransportError::Tampered,
                    )),
                    request_receipts,
                    cost_receipts,
                ));
            }
        };

        let state = if !api.enabled {
            AppSyncEvidenceState::Disabled
        } else if api.updated_at < request.observed_at
            && request
                .observed_at
                .signed_duration_since(api.updated_at)
                .num_seconds()
                > MAX_STALENESS_SECONDS
        {
            AppSyncEvidenceState::Stale
        } else if schema.schema_status.is_failed()
            || schema.deployment_state.is_failed()
            || matches!(schema.schema_status, SchemaCreationStatus::Processing)
            || matches!(schema.deployment_state, DeploymentState::Processing)
        {
            AppSyncEvidenceState::Degraded
        } else {
            AppSyncEvidenceState::Available
        };
        Ok(AwsAppSyncApiResultProposal::new(
            &self.registration,
            self.provider.definition(),
            &request,
            state,
            list_pages,
            list_complete,
            data_pages.len() as u16,
            resolver_pages.len() as u16,
            associations_complete,
            Some(api),
            Some(schema),
            Some(associations),
            None,
            request_receipts,
            cost_receipts,
            self.provider.provenance(),
        ))
    }

    fn collect_data_sources(
        &mut self,
        request: &AppSyncEvidenceRequest,
        request_receipts: &mut Vec<RequestReceipt>,
        cost_receipts: &mut Vec<CostReceipt>,
    ) -> Result<(Vec<AssociationPage>, bool, Option<AwsAppSyncTransportError>)> {
        let mut pages = Vec::new();
        let mut list_request = ListDataSourcesRequest::first(self.scope(), request.page_size)?;
        let mut seen = HashSet::new();
        loop {
            match self.provider.list_data_sources(&list_request) {
                Ok(response) => {
                    request_receipts.push(response.request_receipt.clone());
                    cost_receipts.push(response.cost_receipt.clone());
                    pages.push(response.page().clone());
                    if let Some(cursor) = response.next_cursor.clone() {
                        if validate_cursor_seen(&mut seen, cursor.marker_digest()).is_err() {
                            return Ok((
                                pages,
                                false,
                                Some(AwsAppSyncTransportError::PaginationLoop),
                            ));
                        }
                        if pages.len() as u16 >= request.max_pages {
                            return Ok((pages, false, Some(AwsAppSyncTransportError::Partial)));
                        }
                        list_request = ListDataSourcesRequest::new_with_cursor(
                            self.scope(),
                            request.page_size,
                            Some(cursor),
                        )?;
                    } else {
                        return Ok((pages, true, None));
                    }
                }
                Err(error) => {
                    request_receipts.push(list_request.recorded_request().receipt());
                    cost_receipts.push(CostReceipt::new(
                        AwsAppSyncOperation::ListDataSources.as_str(),
                        0,
                    )?);
                    return Ok((pages, false, Some(error)));
                }
            }
        }
    }

    fn collect_resolvers(
        &mut self,
        request: &AppSyncEvidenceRequest,
        request_receipts: &mut Vec<RequestReceipt>,
        cost_receipts: &mut Vec<CostReceipt>,
    ) -> Result<(Vec<AssociationPage>, bool, Option<AwsAppSyncTransportError>)> {
        let mut pages = Vec::new();
        let mut list_request = ListResolversRequest::first(self.scope(), request.page_size)?;
        let mut seen = HashSet::new();
        loop {
            match self.provider.list_resolvers(&list_request) {
                Ok(response) => {
                    request_receipts.push(response.request_receipt.clone());
                    cost_receipts.push(response.cost_receipt.clone());
                    pages.push(response.page().clone());
                    if let Some(cursor) = response.next_cursor.clone() {
                        if validate_cursor_seen(&mut seen, cursor.marker_digest()).is_err() {
                            return Ok((
                                pages,
                                false,
                                Some(AwsAppSyncTransportError::PaginationLoop),
                            ));
                        }
                        if pages.len() as u16 >= request.max_pages {
                            return Ok((pages, false, Some(AwsAppSyncTransportError::Partial)));
                        }
                        list_request = ListResolversRequest::new_with_cursor(
                            self.scope(),
                            request.page_size,
                            Some(cursor),
                        )?;
                    } else {
                        return Ok((pages, true, None));
                    }
                }
                Err(error) => {
                    request_receipts.push(list_request.recorded_request().receipt());
                    cost_receipts.push(CostReceipt::new(
                        AwsAppSyncOperation::ListResolvers.as_str(),
                        0,
                    )?);
                    return Ok((pages, false, Some(error)));
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn failed_proposal(
        &self,
        request: &AppSyncEvidenceRequest,
        state: AppSyncEvidenceState,
        list_pages: u16,
        list_complete: bool,
        data_source_pages: u16,
        resolver_pages: u16,
        associations_complete: bool,
        api: Option<ApiMetadata>,
        schema: Option<SchemaDeploymentMetadata>,
        associations: Option<AssociationProjection>,
        failure: Option<FailureEvidence>,
        request_receipts: Vec<RequestReceipt>,
        cost_receipts: Vec<CostReceipt>,
    ) -> AwsAppSyncApiResultProposal {
        AwsAppSyncApiResultProposal::new(
            &self.registration,
            self.provider.definition(),
            request,
            state,
            list_pages,
            list_complete,
            data_source_pages,
            resolver_pages,
            associations_complete,
            api,
            schema,
            associations,
            failure,
            request_receipts,
            cost_receipts,
            self.provider.provenance(),
        )
    }

    fn validate_request(&self, request: &AppSyncEvidenceRequest) -> Result<()> {
        self.registration.validate()?;
        if request.scope_digest != *self.registration.scope_digest()
            || request.expected_provider_digest != self.provider.definition().provider_digest
            || request.expected_registration_digest != *self.registration.registration_digest()
        {
            return Err(AwsAppSyncApiResultError::ScopeMismatch);
        }
        if self.registration.secret_reference().is_revoked() {
            return Err(AwsAppSyncApiResultError::SecretRevoked);
        }
        if self.registration.consent().is_revoked() {
            return Err(AwsAppSyncApiResultError::ConsentRevoked);
        }
        if !self
            .registration
            .consent()
            .is_active_at(request.observed_at)
        {
            return Err(AwsAppSyncApiResultError::ConsentExpired);
        }
        Ok(())
    }
}

fn state_for_transport(error: &AwsAppSyncTransportError) -> AppSyncEvidenceState {
    match error {
        AwsAppSyncTransportError::BlockedEnv
        | AwsAppSyncTransportError::Unknown
        | AwsAppSyncTransportError::InvalidResponse => AppSyncEvidenceState::ProviderUnknown,
        AwsAppSyncTransportError::Unauthorized
        | AwsAppSyncTransportError::Forbidden
        | AwsAppSyncTransportError::AccessLost => AppSyncEvidenceState::AccessLost,
        AwsAppSyncTransportError::Partial
        | AwsAppSyncTransportError::RateLimited { .. }
        | AwsAppSyncTransportError::Timeout => AppSyncEvidenceState::Partial,
        AwsAppSyncTransportError::Tampered | AwsAppSyncTransportError::PaginationLoop => {
            AppSyncEvidenceState::Tampered
        }
        AwsAppSyncTransportError::ConfigDrift => AppSyncEvidenceState::Stale,
        AwsAppSyncTransportError::BadRequest
        | AwsAppSyncTransportError::NotFound
        | AwsAppSyncTransportError::Conflict
        | AwsAppSyncTransportError::ServerError { .. } => AppSyncEvidenceState::ProviderUnknown,
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFailure {
    RegistrationInactive,
    RegistrationDigestMismatch,
    ProviderDigestMismatch,
    ApiRevisionDigestMismatch,
    PermissionDigestMismatch,
    ScopeDigestMismatch,
    TamperedEvidence,
    PartialEvidence,
    AccessLoss,
    RevisionDrift,
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
            "aws-appsync-verification-report/v1",
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
