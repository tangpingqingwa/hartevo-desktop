//! Typed Service Catalog service, proposal, recording, verification, and
//! reversible registration.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::{
    API_REVISION, CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_VERSION, PLUGIN_VERSION, PROVIDER_ID,
    SERVICE_ID,
    consumer::MissionAwsServiceCatalogConsumer,
    contract_digest,
    error::{AwsServiceCatalogError, AwsServiceCatalogTransportError, Result},
    model::{
        AwsServiceCatalogScope, Digest, EvidenceState, IdempotencyKey, MissionProjection,
        PermissionSnapshot, ProjectProjection, ProvisionedProductProjection, RecordProjection,
        RevisionFences, SearchQuery, SecretReference, Timestamp, TransportProvenance,
        WorkProductProjection, digest_serializable, mission_projection, project_projection,
        sorted_projection_digests, work_product_projection,
    },
    provider::{
        AwsServiceCatalogOperation, AwsServiceCatalogProvider, AwsServiceCatalogProviderDefinition,
        AwsServiceCatalogTransport, DescribeProvisionedProductRequest, DescribeRecordRequest,
        ListRecordHistoryRequest, ListRecordHistoryResponse, SearchProvisionedProductsRequest,
        SearchProvisionedProductsResponse,
    },
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
            "aws-service-catalog-registration-transition/v1",
            &[
                ("previous", format!("{previous_status:?}")),
                ("new", format!("{new_status:?}")),
                ("registration", registration_digest.to_string()),
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

/// Version/provider/API/permission/scope/secret-bound reversible registration.
#[derive(Clone, Eq, PartialEq)]
pub struct AwsServiceCatalogRegistration {
    id: String,
    plugin_version: String,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    provider_revision: u64,
    provider_digest: Digest,
    api_digest: Digest,
    permission_snapshot: PermissionSnapshot,
    scope: AwsServiceCatalogScope,
    scope_digest: Digest,
    secret_reference: SecretReference,
    registration_revision: u64,
    status: RegistrationStatus,
    registration_digest: Digest,
}

impl AwsServiceCatalogRegistration {
    pub fn new(
        id: impl Into<String>,
        scope: AwsServiceCatalogScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        provider: &AwsServiceCatalogProviderDefinition,
        registration_revision: u64,
    ) -> Result<Self> {
        let id = id.into();
        if id.is_empty() || registration_revision == 0 {
            return Err(AwsServiceCatalogError::InvalidRegistration);
        }
        provider.validate()?;
        scope.validate()?;
        secret_reference.validate(&scope)?;
        permission_snapshot.validate()?;
        let expected_permissions = crate::LAYER1_PERMISSIONS
            .iter()
            .map(|permission| (*permission).to_owned())
            .collect::<BTreeSet<_>>();
        if permission_snapshot.permissions != expected_permissions {
            return Err(AwsServiceCatalogError::InvalidRegistration);
        }
        let mut registration = Self {
            id,
            plugin_version: PLUGIN_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            contract_digest: Digest::parse(CONTRACT_DIGEST.to_owned())?,
            provider_id: provider.provider_id.clone(),
            provider_revision: provider.provider_revision,
            provider_digest: provider.provider_digest.clone(),
            api_digest: provider.api_digest.clone(),
            permission_snapshot,
            scope_digest: scope.digest(),
            scope,
            secret_reference,
            registration_revision,
            status: RegistrationStatus::Active,
            registration_digest: Digest::from_text("unsealed-service-catalog-registration"),
        };
        registration.registration_digest = registration.calculate_digest();
        registration.validate().map(|()| registration)
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

    pub fn scope(&self) -> &AwsServiceCatalogScope {
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
        if self.plugin_version != PLUGIN_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.contract_digest.as_str() != CONTRACT_DIGEST
            || self.contract_digest.as_str() != contract_digest()
            || self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.api_digest != Digest::from_text(API_REVISION)
            || self.registration_revision == 0
            || self.scope_digest != self.scope.digest()
            || self.registration_digest != self.calculate_digest()
        {
            return Err(AwsServiceCatalogError::InvalidRegistration);
        }
        self.scope.validate()?;
        self.permission_snapshot.validate()?;
        self.secret_reference.validate(&self.scope)
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsServiceCatalogError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Revoked;
        self.secret_reference.revoke();
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    pub fn reverse(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsServiceCatalogError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Reversed;
        self.secret_reference.revoke();
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsServiceCatalogError::RegistrationReversed);
        }
        let previous_status = self.status;
        self.status = RegistrationStatus::Active;
        self.secret_reference.restore();
        self.registration_digest = self.calculate_digest();
        Ok(RegistrationTransitionEvidence::new(
            previous_status,
            self.status,
            self.registration_digest.clone(),
        ))
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-service-catalog-registration/v1",
            &[
                ("id", self.id.clone()),
                ("plugin_version", self.plugin_version.clone()),
                ("contract_version", self.contract_version.clone()),
                ("contract", self.contract_digest.to_string()),
                ("provider_id", self.provider_id.clone()),
                ("provider_revision", self.provider_revision.to_string()),
                ("provider", self.provider_digest.to_string()),
                ("api", self.api_digest.to_string()),
                ("permission", self.permission_digest().to_string()),
                ("scope", self.scope_digest.to_string()),
                ("secret", self.secret_reference_digest().to_string()),
                ("revision", self.registration_revision.to_string()),
                ("status", format!("{:?}", self.status)),
            ],
        )
    }
}

impl fmt::Debug for AwsServiceCatalogRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsServiceCatalogRegistration")
            .field("id_digest", &Digest::from_text(&self.id))
            .field("plugin_version", &self.plugin_version)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider_id", &self.provider_id)
            .field("provider_revision", &self.provider_revision)
            .field("provider_digest", &self.provider_digest)
            .field("api_digest", &self.api_digest)
            .field("permission_digest", &self.permission_digest())
            .field("scope_digest", &self.scope_digest)
            .field("secret_reference_digest", &self.secret_reference_digest())
            .field("registration_revision", &self.registration_revision)
            .field("status", &self.status)
            .field("registration_digest", &self.registration_digest)
            .finish()
    }
}

impl Serialize for AwsServiceCatalogRegistration {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AwsServiceCatalogRegistration", 15)?;
        state.serialize_field("idDigest", &Digest::from_text(&self.id))?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("apiDigest", &self.api_digest)?;
        state.serialize_field("permissionDigest", &self.permission_digest())?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("secretReferenceDigest", &self.secret_reference_digest())?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("registrationDigest", &self.registration_digest)?;
        state.serialize_field("native", &false)?;
        state.end()
    }
}

pub type AwsServiceCatalogRegistrationAlias = AwsServiceCatalogRegistration;

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
    pub durable_provider_receipt: bool,
    pub outcome_adoption: bool,
    pub work_product_adoption: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsServiceCatalogEvidenceRequest {
    pub scope_digest: Digest,
    pub expected_provider_digest: Digest,
    pub expected_api_digest: Digest,
    pub expected_registration_digest: Digest,
    pub query: SearchQuery,
    pub search_page_size: u16,
    pub history_page_size: u16,
    pub max_search_pages: u16,
    pub max_history_pages: u16,
    pub observed_at: Timestamp,
    pub idempotency_digest: Digest,
    pub revision_fences: RevisionFences,
    pub request_digest: Digest,
}

impl AwsServiceCatalogEvidenceRequest {
    #[allow(clippy::too_many_arguments)]
    fn bind(
        scope: &AwsServiceCatalogScope,
        provider: &AwsServiceCatalogProviderDefinition,
        registration: &AwsServiceCatalogRegistration,
        query: SearchQuery,
        search_page_size: u16,
        history_page_size: u16,
        max_search_pages: u16,
        max_history_pages: u16,
        observed_at: impl Into<String>,
        idempotency_key: IdempotencyKey,
    ) -> Result<Self> {
        scope.validate()?;
        query.validate()?;
        if !(1..=crate::MAX_SEARCH_PAGE_SIZE).contains(&search_page_size) {
            return Err(AwsServiceCatalogError::InvalidSearchPageSize);
        }
        if !(1..=crate::MAX_HISTORY_PAGE_SIZE).contains(&history_page_size) {
            return Err(AwsServiceCatalogError::InvalidHistoryPageSize);
        }
        if max_search_pages == 0
            || max_search_pages > crate::MAX_PAGES
            || max_history_pages == 0
            || max_history_pages > crate::MAX_PAGES
        {
            return Err(AwsServiceCatalogError::InvalidPageCount);
        }
        let observed_at = Timestamp::new(observed_at)?;
        let revision_fences = RevisionFences::from_scope(scope);
        let mut request = Self {
            scope_digest: scope.digest(),
            expected_provider_digest: provider.provider_digest.clone(),
            expected_api_digest: provider.api_digest.clone(),
            expected_registration_digest: registration.registration_digest.clone(),
            query,
            search_page_size,
            history_page_size,
            max_search_pages,
            max_history_pages,
            observed_at,
            idempotency_digest: idempotency_key.digest().clone(),
            revision_fences,
            request_digest: Digest::from_text("unsealed-service-catalog-evidence-request"),
        };
        request.request_digest = request.calculate_digest();
        Ok(request)
    }

    pub fn digest(&self) -> &Digest {
        &self.request_digest
    }

    fn calculate_digest(&self) -> Digest {
        digest_serializable(&(
            &self.scope_digest,
            &self.expected_provider_digest,
            &self.expected_api_digest,
            &self.expected_registration_digest,
            &self.query,
            self.search_page_size,
            self.history_page_size,
            self.max_search_pages,
            self.max_history_pages,
            &self.observed_at,
            &self.idempotency_digest,
            &self.revision_fences,
        ))
    }

    fn validate_against<T: AwsServiceCatalogTransport>(
        &self,
        service: &AwsServiceCatalogProvisionedResultService<T>,
    ) -> Result<()> {
        if self.revision_fences.mission_revision != service.registration.scope().mission.revision {
            return Err(AwsServiceCatalogError::StaleMission);
        }
        if self.scope_digest != *service.registration.scope_digest()
            || self.expected_provider_digest != service.provider.definition().provider_digest
            || self.expected_api_digest != service.provider.definition().api_digest
            || self.expected_registration_digest != *service.registration.registration_digest()
            || self.request_digest != self.calculate_digest()
        {
            return Err(AwsServiceCatalogError::ScopeMismatch);
        }
        self.revision_fences
            .validate_against(service.registration.scope())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceDigests {
    pub plugin_version_digest: Digest,
    pub contract_digest: Digest,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub permission_digest: Digest,
    pub scope_digest: Digest,
    pub search_digest: Option<Digest>,
    pub history_digest: Option<Digest>,
    pub describe_provisioned_product_digest: Option<Digest>,
    pub describe_record_digest: Option<Digest>,
    pub evidence_digest: Digest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailureEvidence {
    pub operation: AwsServiceCatalogOperation,
    pub status_code: Option<u16>,
    pub category: String,
    pub failure_digest: Digest,
}

impl FailureEvidence {
    fn from_transport(
        operation: AwsServiceCatalogOperation,
        error: &AwsServiceCatalogTransportError,
    ) -> Self {
        let category = match error {
            AwsServiceCatalogTransportError::BlockedEnv => "blocked_env",
            AwsServiceCatalogTransportError::BadRequest => "bad_request",
            AwsServiceCatalogTransportError::Unauthorized => "unauthorized",
            AwsServiceCatalogTransportError::Forbidden => "forbidden",
            AwsServiceCatalogTransportError::NotFound => "not_found",
            AwsServiceCatalogTransportError::RateLimited => "throttled",
            AwsServiceCatalogTransportError::ServerError => "server_error",
            AwsServiceCatalogTransportError::Timeout => "timeout",
            AwsServiceCatalogTransportError::AccessLost => "access_loss",
            AwsServiceCatalogTransportError::Partial => "partial",
            AwsServiceCatalogTransportError::InvalidResponse => "invalid_response",
        }
        .to_owned();
        Self {
            operation,
            status_code: error.status_code(),
            failure_digest: Digest::from_parts(
                "aws-service-catalog-failure/v1",
                &[
                    ("operation", operation.as_str().to_owned()),
                    ("category", category.clone()),
                    (
                        "status",
                        error
                            .status_code()
                            .map_or_else(String::new, |code| code.to_string()),
                    ),
                ],
            ),
            category,
        }
    }

    fn from_error(operation: AwsServiceCatalogOperation, error: &AwsServiceCatalogError) -> Self {
        let category = match error {
            AwsServiceCatalogError::CursorLoop => "cursor_loop",
            AwsServiceCatalogError::CursorTampered => "cursor_tampered",
            AwsServiceCatalogError::ReplayRejected => "replay_rejected",
            AwsServiceCatalogError::StaleMission => "stale_mission",
            AwsServiceCatalogError::RevisionMismatch => "revision_mismatch",
            AwsServiceCatalogError::ScopeViolation | AwsServiceCatalogError::ScopeMismatch => {
                "scope_mismatch"
            }
            AwsServiceCatalogError::ResponseIntegrity
            | AwsServiceCatalogError::TamperedEvidence => "tampered",
            AwsServiceCatalogError::Transport(error) => {
                return Self::from_transport(operation, error);
            }
            _ => "provider_unknown",
        }
        .to_owned();
        Self {
            operation,
            status_code: None,
            failure_digest: Digest::from_parts(
                "aws-service-catalog-logical-failure/v1",
                &[
                    ("operation", operation.as_str().to_owned()),
                    ("category", category.clone()),
                ],
            ),
            category,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsServiceCatalogProvisionedResultProposal {
    pub service_id: String,
    pub consumer_id: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub account_digest: Digest,
    pub region_digest: Digest,
    pub access_level_digest: Digest,
    pub portfolio_digest: Digest,
    pub product_digest: Digest,
    pub artifact_digest: Digest,
    pub provisioned_product_digest: Digest,
    pub record_digest: Digest,
    pub project: ProjectProjection,
    pub mission: MissionProjection,
    pub work_product: WorkProductProjection,
    pub status: Option<crate::model::ProvisionedProductStatus>,
    pub search_pages: u16,
    pub history_pages: u16,
    pub search_complete: bool,
    pub history_complete: bool,
    pub product: Option<ProvisionedProductProjection>,
    pub records: Vec<RecordProjection>,
    pub selected_record: Option<RecordProjection>,
    pub state: EvidenceState,
    pub failure: Option<FailureEvidence>,
    pub observed_at: Timestamp,
    pub revision_fences: RevisionFences,
    pub evidence: EvidenceDigests,
    pub idempotency_digest: Digest,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub proposal_digest: Digest,
}

impl AwsServiceCatalogProvisionedResultProposal {
    #[allow(clippy::too_many_arguments)]
    fn build<T: AwsServiceCatalogTransport>(
        service: &AwsServiceCatalogProvisionedResultService<T>,
        request: &AwsServiceCatalogEvidenceRequest,
        state: EvidenceState,
        search_pages: u16,
        history_pages: u16,
        search_complete: bool,
        history_complete: bool,
        product: Option<ProvisionedProductProjection>,
        records: Vec<RecordProjection>,
        selected_record: Option<RecordProjection>,
        failure: Option<FailureEvidence>,
        search_digest: Option<Digest>,
        history_digest: Option<Digest>,
        describe_product_digest: Option<Digest>,
        describe_record_digest: Option<Digest>,
    ) -> Self {
        let scope = service.registration.scope();
        let status = product.as_ref().map(|value| value.status.clone());
        let mut evidence = EvidenceDigests {
            plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_digest: service.registration.contract_digest.clone(),
            provider_digest: service.provider.definition().provider_digest.clone(),
            api_digest: service.provider.definition().api_digest.clone(),
            permission_digest: service.registration.permission_digest(),
            scope_digest: service.registration.scope_digest.clone(),
            search_digest,
            history_digest,
            describe_provisioned_product_digest: describe_product_digest,
            describe_record_digest,
            evidence_digest: Digest::from_text("unsealed-service-catalog-evidence"),
        };
        evidence.evidence_digest = calculate_evidence_digest(
            &evidence,
            state,
            search_pages,
            history_pages,
            search_complete,
            history_complete,
            product.as_ref(),
            &records,
            selected_record.as_ref(),
            failure.as_ref(),
        );
        let mut proposal = Self {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            registration_digest: service.registration.registration_digest.clone(),
            scope_digest: service.registration.scope_digest.clone(),
            account_digest: scope.account_id_digest.clone(),
            region_digest: scope.region.digest(),
            access_level_digest: scope.access_level.digest(),
            portfolio_digest: scope.portfolio.portfolio_id_digest.clone(),
            product_digest: scope.product.product_id_digest.clone(),
            artifact_digest: scope.product.artifact_id_digest.clone(),
            provisioned_product_digest: scope
                .provisioned_product
                .provisioned_product_id_digest
                .clone(),
            record_digest: scope.record.record_id_digest.clone(),
            project: project_projection(&scope.project),
            mission: mission_projection(&scope.mission),
            work_product: work_product_projection(&scope.work_product),
            status,
            search_pages,
            history_pages,
            search_complete,
            history_complete,
            product,
            records,
            selected_record,
            state,
            failure,
            observed_at: request.observed_at.clone(),
            revision_fences: request.revision_fences.clone(),
            evidence,
            idempotency_digest: request.idempotency_digest.clone(),
            provenance: service.provider.provenance(),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            proposal_digest: Digest::from_text("unsealed-service-catalog-proposal"),
        };
        proposal.proposal_digest = proposal.calculate_digest();
        proposal
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

    pub fn validate_integrity(&self) -> Result<()> {
        if self.service_id != SERVICE_ID
            || self.consumer_id != CONSUMER_ID
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.evidence.evidence_digest
                != calculate_evidence_digest(
                    &self.evidence,
                    self.state,
                    self.search_pages,
                    self.history_pages,
                    self.search_complete,
                    self.history_complete,
                    self.product.as_ref(),
                    &self.records,
                    self.selected_record.as_ref(),
                    self.failure.as_ref(),
                )
            || self.proposal_digest != self.calculate_digest()
        {
            return Err(AwsServiceCatalogError::TamperedEvidence);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        let material = serde_json::json!({
            "serviceId": self.service_id,
            "consumerId": self.consumer_id,
            "registrationDigest": self.registration_digest,
            "scopeDigest": self.scope_digest,
            "accountDigest": self.account_digest,
            "regionDigest": self.region_digest,
            "accessLevelDigest": self.access_level_digest,
            "portfolioDigest": self.portfolio_digest,
            "productDigest": self.product_digest,
            "artifactDigest": self.artifact_digest,
            "provisionedProductDigest": self.provisioned_product_digest,
            "recordDigest": self.record_digest,
            "project": self.project,
            "mission": self.mission,
            "workProduct": self.work_product,
            "status": self.status,
            "searchPages": self.search_pages,
            "historyPages": self.history_pages,
            "searchComplete": self.search_complete,
            "historyComplete": self.history_complete,
            "product": self.product,
            "records": self.records,
            "selectedRecord": self.selected_record,
            "state": self.state,
            "failure": self.failure,
            "observedAt": self.observed_at,
            "revisionFences": self.revision_fences,
            "evidence": self.evidence,
            "idempotencyDigest": self.idempotency_digest,
            "provenance": self.provenance,
            "connected": self.connected,
            "native": self.native,
            "firstParty": self.first_party,
            "providerReceipt": self.provider_receipt,
            "outcomeAdopted": self.outcome_adopted,
            "workProductAdopted": self.work_product_adopted,
        });
        digest_serializable(&material)
    }
}

fn calculate_evidence_digest(
    evidence: &EvidenceDigests,
    state: EvidenceState,
    search_pages: u16,
    history_pages: u16,
    search_complete: bool,
    history_complete: bool,
    product: Option<&ProvisionedProductProjection>,
    records: &[RecordProjection],
    selected_record: Option<&RecordProjection>,
    failure: Option<&FailureEvidence>,
) -> Digest {
    let material = serde_json::json!({
        "pluginVersionDigest": evidence.plugin_version_digest,
        "contractDigest": evidence.contract_digest,
        "providerDigest": evidence.provider_digest,
        "apiDigest": evidence.api_digest,
        "permissionDigest": evidence.permission_digest,
        "scopeDigest": evidence.scope_digest,
        "searchDigest": evidence.search_digest,
        "historyDigest": evidence.history_digest,
        "describeProvisionedProductDigest": evidence.describe_provisioned_product_digest,
        "describeRecordDigest": evidence.describe_record_digest,
        "state": state,
        "searchPages": search_pages,
        "historyPages": history_pages,
        "searchComplete": search_complete,
        "historyComplete": history_complete,
        "product": product,
        "records": records,
        "selectedRecord": selected_record,
        "failure": failure,
    });
    digest_serializable(&material)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedAwsServiceCatalogResult {
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub state: EvidenceState,
    pub provenance: TransportProvenance,
    pub review_only: bool,
    pub durable_provider_receipt: bool,
    pub connected: bool,
    pub native: bool,
    pub work_product_adopted: bool,
    pub outcome_adopted: bool,
    pub record_digest: Digest,
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
    RevisionFenceMismatch,
    EvidenceDigestMismatch,
    ProposalDigestMismatch,
    TamperedEvidence,
    PartialEvidence,
    AccessLoss,
    ProviderUnknown,
    CursorLoop,
    CursorTampered,
    ReplayRejected,
    StaleMission,
    Throttled,
    RevisionMismatch,
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
    fn new(valid: bool, review_eligible: bool, mut failures: Vec<VerificationFailure>) -> Self {
        failures.sort_unstable();
        failures.dedup();
        let verification_digest = digest_serializable(&(valid, review_eligible, &failures));
        Self {
            valid,
            review_eligible,
            failures,
            verification_digest,
        }
    }
}

pub struct AwsServiceCatalogProvisionedResultService<T: AwsServiceCatalogTransport> {
    registration: AwsServiceCatalogRegistration,
    provider: AwsServiceCatalogProvider<T>,
    idempotency: BTreeMap<Digest, (Digest, AwsServiceCatalogProvisionedResultProposal)>,
}

impl<T: AwsServiceCatalogTransport> fmt::Debug for AwsServiceCatalogProvisionedResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsServiceCatalogProvisionedResultService")
            .field("registration", &self.registration)
            .field("provider", &self.provider)
            .field("idempotency_count", &self.idempotency.len())
            .finish()
    }
}

impl<T: AwsServiceCatalogTransport> AwsServiceCatalogProvisionedResultService<T> {
    pub fn new(
        scope: AwsServiceCatalogScope,
        secret_reference: SecretReference,
        provider: AwsServiceCatalogProvider<T>,
    ) -> Result<Self> {
        Self::with_registration(
            "aws-service-catalog-registration",
            scope,
            secret_reference,
            PermissionSnapshot::for_layer_one(1),
            provider,
            1,
        )
    }

    pub fn with_registration(
        registration_id: impl Into<String>,
        scope: AwsServiceCatalogScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        provider: AwsServiceCatalogProvider<T>,
        registration_revision: u64,
    ) -> Result<Self> {
        let registration = AwsServiceCatalogRegistration::new(
            registration_id,
            scope,
            secret_reference,
            permission_snapshot,
            provider.definition(),
            registration_revision,
        )?;
        Ok(Self {
            registration,
            provider,
            idempotency: BTreeMap::new(),
        })
    }

    pub fn describe_capabilities(&self) -> CapabilityDescription {
        CapabilityDescription {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            operations: AwsServiceCatalogOperation::ALL
                .iter()
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
            durable_provider_receipt: false,
            outcome_adoption: false,
            work_product_adoption: false,
        }
    }

    pub fn registration(&self) -> &AwsServiceCatalogRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut AwsServiceCatalogRegistration {
        &mut self.registration
    }

    pub fn scope(&self) -> &AwsServiceCatalogScope {
        self.registration.scope()
    }

    pub fn provider(&self) -> &AwsServiceCatalogProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsServiceCatalogProvider<T> {
        &mut self.provider
    }

    pub fn request(
        &self,
        idempotency_key: impl AsRef<str>,
        query: SearchQuery,
        search_page_size: u16,
        history_page_size: u16,
        max_search_pages: u16,
        max_history_pages: u16,
        observed_at: impl Into<String>,
    ) -> Result<AwsServiceCatalogEvidenceRequest> {
        let idempotency_key = IdempotencyKey::new(idempotency_key)?;
        AwsServiceCatalogEvidenceRequest::bind(
            self.scope(),
            self.provider.definition(),
            &self.registration,
            query,
            search_page_size,
            history_page_size,
            max_search_pages,
            max_history_pages,
            observed_at,
            idempotency_key,
        )
    }

    pub fn default_request(
        &self,
        idempotency_key: impl AsRef<str>,
        observed_at: impl Into<String>,
    ) -> Result<AwsServiceCatalogEvidenceRequest> {
        self.request(idempotency_key, SearchQuery::All, 10, 10, 1, 1, observed_at)
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

    pub fn consumer(&self) -> Result<MissionAwsServiceCatalogConsumer> {
        MissionAwsServiceCatalogConsumer::new(self.scope().clone(), self.registration.clone())
    }

    fn ensure_active(&self) -> Result<()> {
        self.registration.validate()?;
        if !self.registration.is_active() || self.registration.secret_reference().is_revoked() {
            return Err(AwsServiceCatalogError::RegistrationInactive);
        }
        Ok(())
    }

    fn ensure_request_scope(&self, scope: &AwsServiceCatalogScope) -> Result<()> {
        if scope.digest() != *self.registration.scope_digest() {
            return Err(AwsServiceCatalogError::ScopeMismatch);
        }
        Ok(())
    }

    pub fn search_provisioned_products(
        &mut self,
        request: &SearchProvisionedProductsRequest,
    ) -> Result<SearchProvisionedProductsResponse> {
        self.ensure_active()?;
        self.ensure_request_scope(request.scope())?;
        let response = self.provider.search_provisioned_products(request)?;
        response.validate()?;
        crate::provider::validate_response_scope(self.scope(), &response.items, &[])?;
        let mut items = response.items;
        items.sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));
        if items
            .windows(2)
            .any(|window| window[0].sort_key() == window[1].sort_key())
        {
            return Err(AwsServiceCatalogError::ReplayRejected);
        }
        Ok(SearchProvisionedProductsResponse::new(
            items,
            response.next_page_token,
        ))
    }

    pub fn describe_provisioned_product(
        &mut self,
        request: &DescribeProvisionedProductRequest,
    ) -> Result<crate::provider::DescribeProvisionedProductResponse> {
        self.ensure_active()?;
        self.ensure_request_scope(request.scope())?;
        let response = self.provider.describe_provisioned_product(request)?;
        response.validate()?;
        if !response.projection.matches_scope(self.scope()) {
            return Err(AwsServiceCatalogError::ScopeViolation);
        }
        Ok(response)
    }

    pub fn list_record_history(
        &mut self,
        request: &ListRecordHistoryRequest,
    ) -> Result<ListRecordHistoryResponse> {
        self.ensure_active()?;
        self.ensure_request_scope(request.scope())?;
        let response = self.provider.list_record_history(request)?;
        response.validate()?;
        crate::provider::validate_response_scope(self.scope(), &[], &response.records)?;
        let mut records = response.records;
        records.sort_by(|left, right| {
            right
                .sort_key()
                .cmp(&left.sort_key())
                .then_with(|| left.record_digest.cmp(&right.record_digest))
        });
        if records
            .windows(2)
            .any(|window| window[0].record_digest == window[1].record_digest)
        {
            return Err(AwsServiceCatalogError::ReplayRejected);
        }
        Ok(ListRecordHistoryResponse::new(
            records,
            response.next_page_token,
        ))
    }

    pub fn describe_record(
        &mut self,
        request: &DescribeRecordRequest,
    ) -> Result<crate::provider::DescribeRecordResponse> {
        self.ensure_active()?;
        self.ensure_request_scope(request.scope())?;
        let response = self.provider.describe_record(request)?;
        response.validate()?;
        let record = &response.projection;
        if record.record_digest != self.scope().record.record_id_digest
            || record.provisioned_product_digest
                != self
                    .scope()
                    .provisioned_product
                    .provisioned_product_id_digest
        {
            return Err(AwsServiceCatalogError::ScopeViolation);
        }
        Ok(response)
    }

    pub fn propose(
        &mut self,
        request: AwsServiceCatalogEvidenceRequest,
    ) -> Result<AwsServiceCatalogProvisionedResultProposal> {
        self.ensure_active()?;
        request.validate_against(self)?;
        let key = request.idempotency_digest.clone();
        if let Some((request_digest, proposal)) = self.idempotency.get(&key) {
            if request_digest == request.digest() {
                return Ok(proposal.clone());
            }
            return Err(AwsServiceCatalogError::IdempotencyConflict);
        }

        let mut search_pages = 0_u16;
        let mut history_pages = 0_u16;
        let mut search_complete = false;
        let mut history_complete = false;
        let mut search_token = None;
        let mut history_token = None;
        let mut seen_search_tokens = BTreeSet::new();
        let mut seen_history_tokens = BTreeSet::new();
        let mut products = Vec::new();
        let mut records = Vec::new();
        let mut product = None;
        let mut selected_record = None;
        let mut failure = None;
        let mut state = EvidenceState::Ready;
        let mut search_digest = None;
        let mut history_digest = None;
        let mut describe_product_digest = None;
        let mut describe_record_digest = None;

        while search_pages < request.max_search_pages {
            let page_request = SearchProvisionedProductsRequest::new(
                self.scope(),
                request.query.clone(),
                request.search_page_size,
                search_token.clone(),
            )?;
            let response = match self.search_provisioned_products(&page_request) {
                Ok(response) => response,
                Err(error) => {
                    state = state_from_error(&error);
                    failure = Some(FailureEvidence::from_error(
                        AwsServiceCatalogOperation::SearchProvisionedProducts,
                        &error,
                    ));
                    break;
                }
            };
            search_pages += 1;
            for item in response.items {
                if products.iter().any(|seen: &ProvisionedProductProjection| {
                    seen.provisioned_product_digest == item.provisioned_product_digest
                }) {
                    state = EvidenceState::ReplayRejected;
                    failure = Some(FailureEvidence::from_error(
                        AwsServiceCatalogOperation::SearchProvisionedProducts,
                        &AwsServiceCatalogError::ReplayRejected,
                    ));
                    break;
                }
                products.push(item);
            }
            if failure.is_some() {
                break;
            }
            search_digest = Some(digest_serializable(&products));
            if let Some(next_token) = response.next_page_token {
                if next_token.page_number() <= page_request.page_number()
                    || !seen_search_tokens.insert(next_token.digest())
                {
                    state = EvidenceState::CursorLoop;
                    failure = Some(FailureEvidence::from_error(
                        AwsServiceCatalogOperation::SearchProvisionedProducts,
                        &AwsServiceCatalogError::CursorLoop,
                    ));
                    break;
                }
                if next_token != page_request.next_page_token() {
                    state = EvidenceState::CursorTampered;
                    failure = Some(FailureEvidence::from_error(
                        AwsServiceCatalogOperation::SearchProvisionedProducts,
                        &AwsServiceCatalogError::CursorTampered,
                    ));
                    break;
                }
                search_token = Some(next_token);
            } else {
                search_complete = true;
                break;
            }
        }
        if !search_complete && failure.is_none() {
            state = EvidenceState::Partial;
        }

        if failure.is_none() && !products.is_empty() {
            let describe_request = DescribeProvisionedProductRequest::new(self.scope())?;
            match self.describe_provisioned_product(&describe_request) {
                Ok(response) => {
                    describe_product_digest = Some(response.response_digest.clone());
                    product = Some(response.projection);
                }
                Err(error) => {
                    state = state_from_error(&error);
                    failure = Some(FailureEvidence::from_error(
                        AwsServiceCatalogOperation::DescribeProvisionedProduct,
                        &error,
                    ));
                }
            }
        }

        if failure.is_none() && product.is_some() {
            while history_pages < request.max_history_pages {
                let page_request = ListRecordHistoryRequest::new(
                    self.scope(),
                    request.history_page_size,
                    history_token.clone(),
                )?;
                let response = match self.list_record_history(&page_request) {
                    Ok(response) => response,
                    Err(error) => {
                        state = state_from_error(&error);
                        failure = Some(FailureEvidence::from_error(
                            AwsServiceCatalogOperation::ListRecordHistory,
                            &error,
                        ));
                        break;
                    }
                };
                history_pages += 1;
                records.extend(response.records);
                history_digest = Some(digest_serializable(&records));
                if let Some(next_token) = response.next_page_token {
                    if next_token.page_number() <= page_request.page_number()
                        || !seen_history_tokens.insert(next_token.digest())
                    {
                        state = EvidenceState::CursorLoop;
                        failure = Some(FailureEvidence::from_error(
                            AwsServiceCatalogOperation::ListRecordHistory,
                            &AwsServiceCatalogError::CursorLoop,
                        ));
                        break;
                    }
                    if next_token != page_request.next_page_token() {
                        state = EvidenceState::CursorTampered;
                        failure = Some(FailureEvidence::from_error(
                            AwsServiceCatalogOperation::ListRecordHistory,
                            &AwsServiceCatalogError::CursorTampered,
                        ));
                        break;
                    }
                    history_token = Some(next_token);
                } else {
                    history_complete = true;
                    break;
                }
            }
            if !history_complete && failure.is_none() {
                state = EvidenceState::Partial;
            }
        }

        if failure.is_none() && product.is_some() {
            let describe_request = DescribeRecordRequest::new(self.scope())?;
            match self.describe_record(&describe_request) {
                Ok(response) => {
                    describe_record_digest = Some(response.response_digest.clone());
                    selected_record = Some(response.projection);
                }
                Err(error) => {
                    state = state_from_error(&error);
                    failure = Some(FailureEvidence::from_error(
                        AwsServiceCatalogOperation::DescribeRecord,
                        &error,
                    ));
                }
            }
        }

        if products.is_empty() && failure.is_none() {
            state = EvidenceState::NotFound;
        } else if failure.is_none() && search_complete && history_complete {
            state = product
                .as_ref()
                .map_or(EvidenceState::ProviderUnknown, |value| match value.status {
                    crate::model::ProvisionedProductStatus::Available => EvidenceState::Available,
                    crate::model::ProvisionedProductStatus::UnderChange => {
                        EvidenceState::UnderChange
                    }
                    crate::model::ProvisionedProductStatus::Tainted => EvidenceState::Tainted,
                    crate::model::ProvisionedProductStatus::Error => EvidenceState::Error,
                    crate::model::ProvisionedProductStatus::Terminated => EvidenceState::Terminated,
                    crate::model::ProvisionedProductStatus::Unknown => {
                        EvidenceState::ProviderUnknown
                    }
                });
        }

        if let Some(value) = &product {
            if value.status == crate::model::ProvisionedProductStatus::Unknown && failure.is_none()
            {
                state = EvidenceState::ProviderUnknown;
            }
        }
        if let Some(value) = &selected_record {
            if !records
                .iter()
                .any(|record| record.record_digest == value.record_digest)
            {
                records.push(value.clone());
            }
        }
        records.sort_by(|left, right| {
            right
                .sort_key()
                .cmp(&left.sort_key())
                .then_with(|| left.record_digest.cmp(&right.record_digest))
        });
        let _ = sorted_projection_digests(product.as_slice(), &records);
        let proposal = AwsServiceCatalogProvisionedResultProposal::build(
            self,
            &request,
            state,
            search_pages,
            history_pages,
            search_complete,
            history_complete,
            product,
            records,
            selected_record,
            failure,
            search_digest,
            history_digest,
            describe_product_digest,
            describe_record_digest,
        );
        proposal.validate_integrity()?;
        self.idempotency
            .insert(key, (request.digest().clone(), proposal.clone()));
        Ok(proposal)
    }

    pub fn record(
        &self,
        proposal: &AwsServiceCatalogProvisionedResultProposal,
    ) -> Result<RecordedAwsServiceCatalogResult> {
        self.ensure_active()?;
        proposal.validate_integrity()?;
        if proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != *self.registration.scope_digest()
        {
            return Err(AwsServiceCatalogError::ScopeMismatch);
        }
        Ok(RecordedAwsServiceCatalogResult {
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            state: proposal.state,
            provenance: proposal.provenance,
            review_only: true,
            durable_provider_receipt: false,
            connected: false,
            native: false,
            work_product_adopted: false,
            outcome_adopted: false,
            record_digest: proposal.record_digest.clone(),
        })
    }

    pub fn verify(
        &self,
        proposal: &AwsServiceCatalogProvisionedResultProposal,
    ) -> VerificationReport {
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
        if proposal.evidence.api_digest != self.provider.definition().api_digest {
            failures.push(VerificationFailure::ApiDigestMismatch);
        }
        if proposal.evidence.permission_digest != self.registration.permission_digest() {
            failures.push(VerificationFailure::PermissionDigestMismatch);
        }
        if proposal.scope_digest != *self.registration.scope_digest() {
            failures.push(VerificationFailure::ScopeDigestMismatch);
        }
        if proposal
            .revision_fences
            .validate_against(self.scope())
            .is_err()
        {
            failures.push(VerificationFailure::RevisionFenceMismatch);
        }
        if proposal.validate_integrity().is_err() {
            failures.push(VerificationFailure::TamperedEvidence);
        }
        match proposal.state {
            EvidenceState::Partial => failures.push(VerificationFailure::PartialEvidence),
            EvidenceState::AccessLoss => failures.push(VerificationFailure::AccessLoss),
            EvidenceState::ProviderUnknown => failures.push(VerificationFailure::ProviderUnknown),
            EvidenceState::CursorLoop => failures.push(VerificationFailure::CursorLoop),
            EvidenceState::CursorTampered => failures.push(VerificationFailure::CursorTampered),
            EvidenceState::ReplayRejected => failures.push(VerificationFailure::ReplayRejected),
            EvidenceState::StaleMission => failures.push(VerificationFailure::StaleMission),
            EvidenceState::Throttled => failures.push(VerificationFailure::Throttled),
            EvidenceState::RevisionMismatch => failures.push(VerificationFailure::RevisionMismatch),
            EvidenceState::Ready
            | EvidenceState::Available
            | EvidenceState::UnderChange
            | EvidenceState::Tainted
            | EvidenceState::Error
            | EvidenceState::Terminated
            | EvidenceState::RegistrationRevoked
            | EvidenceState::NotFound => {}
        }
        let valid = failures.is_empty();
        VerificationReport::new(
            valid,
            valid && proposal.state == EvidenceState::Available,
            failures,
        )
    }
}

fn state_from_error(error: &AwsServiceCatalogError) -> EvidenceState {
    match error {
        AwsServiceCatalogError::CursorLoop => EvidenceState::CursorLoop,
        AwsServiceCatalogError::CursorTampered => EvidenceState::CursorTampered,
        AwsServiceCatalogError::ReplayRejected => EvidenceState::ReplayRejected,
        AwsServiceCatalogError::StaleMission => EvidenceState::StaleMission,
        AwsServiceCatalogError::RevisionMismatch => EvidenceState::RevisionMismatch,
        AwsServiceCatalogError::Transport(AwsServiceCatalogTransportError::AccessLost)
        | AwsServiceCatalogError::AccessLost => EvidenceState::AccessLoss,
        AwsServiceCatalogError::Transport(AwsServiceCatalogTransportError::RateLimited) => {
            EvidenceState::Throttled
        }
        AwsServiceCatalogError::Transport(AwsServiceCatalogTransportError::NotFound) => {
            EvidenceState::NotFound
        }
        _ => EvidenceState::ProviderUnknown,
    }
}

pub type AwsServiceCatalogProvisionedResultRegistration = AwsServiceCatalogRegistration;
