use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::consumer::MissionAwsAthenaConsumer;
use crate::error::{AwsAthenaQueryResultError, AwsAthenaTransportError, Result};
use crate::model::{
    AthenaExecutionState, AthenaQueryResultStatus, AwsAthenaQueryResultScope, ConsentScope,
    CostReceipt, Digest, EvidenceDigests, MissionProjection, OpaquePageToken, PermissionSnapshot,
    ProjectProjection, QueryExecutionMetadata, QueryResultsProjection, RequestReceipt,
    ResultBounds, SecretReference, TransportProvenance, WorkProductProjection, mission_projection,
    project_projection, work_product_projection,
};
use crate::provider::{
    AwsAthenaOperation, AwsAthenaProvider, AwsAthenaProviderDefinition, GetQueryExecutionRequest,
    GetQueryResultsRequest,
};
use crate::query::ParameterizedAthenaQuery;
use crate::{
    CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_VERSION, EVIDENCE_CONTRACT_DIGEST, PLUGIN_VERSION,
    PROVIDER_ID, SERVICE_ID, contract_digest,
};

pub const API_REVISION: &str = crate::PROVIDER_API_REVISION;

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
            "aws-athena-registration-transition/v1",
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
pub struct AwsAthenaQueryResultRegistration {
    id: String,
    plugin_version: String,
    version_digest: Digest,
    contract_version: String,
    contract_digest: Digest,
    provider_id: String,
    provider_revision: u64,
    provider_release: String,
    provider_digest: Digest,
    api_revision: String,
    api_revision_digest: Digest,
    permission_snapshot: PermissionSnapshot,
    consent: ConsentScope,
    scope: AwsAthenaQueryResultScope,
    scope_digest: Digest,
    secret_reference: SecretReference,
    evidence_digest: Digest,
    registration_revision: u64,
    status: RegistrationStatus,
    binding_digest: Digest,
}

impl AwsAthenaQueryResultRegistration {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        scope: AwsAthenaQueryResultScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        consent: ConsentScope,
        provider: &AwsAthenaProviderDefinition,
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
            api_revision: API_REVISION.to_owned(),
            api_revision_digest: Digest::from_text(API_REVISION),
            permission_snapshot,
            consent,
            scope_digest: scope.digest(),
            scope,
            secret_reference,
            evidence_digest: Digest::parse(EVIDENCE_CONTRACT_DIGEST.to_owned())?,
            registration_revision,
            status: RegistrationStatus::Active,
            binding_digest: Digest::from_text("unsealed-athena-registration"),
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

    pub fn api_revision(&self) -> &str {
        &self.api_revision
    }

    pub fn api_revision_digest(&self) -> &Digest {
        &self.api_revision_digest
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

    pub fn scope(&self) -> &AwsAthenaQueryResultScope {
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

    pub fn evidence_digest(&self) -> &Digest {
        &self.evidence_digest
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
            || self.contract_digest.as_str() != contract_digest()
            || self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.provider_release.is_empty()
            || self.api_revision != API_REVISION
            || self.api_revision_digest != Digest::from_text(API_REVISION)
            || self.registration_revision == 0
            || self.scope_digest != self.scope.digest()
            || self.evidence_digest.as_str() != EVIDENCE_CONTRACT_DIGEST
            || self.binding_digest != self.calculate_binding_digest()
        {
            return Err(AwsAthenaQueryResultError::InvalidRegistration);
        }
        self.permission_snapshot.validate()?;
        if self.permission_snapshot.digest() != *self.scope.permission_digest() {
            return Err(AwsAthenaQueryResultError::ScopeMismatch);
        }
        self.scope.validate()?;
        self.secret_reference.validate(&self.scope)?;
        if self
            .permission_snapshot
            .permissions()
            .iter()
            .any(|permission| !self.consent.permissions().contains(permission))
        {
            return Err(AwsAthenaQueryResultError::InvalidConsent);
        }
        if self.consent.is_revoked() {
            return Err(AwsAthenaQueryResultError::ConsentRevoked);
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        if matches!(self.status, RegistrationStatus::Reversed) {
            return Err(AwsAthenaQueryResultError::RegistrationReversed);
        }
        if matches!(self.status, RegistrationStatus::Revoked) {
            return Err(AwsAthenaQueryResultError::RegistrationRevoked);
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
            return Err(AwsAthenaQueryResultError::RegistrationReversed);
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
            return Err(AwsAthenaQueryResultError::RegistrationReversed);
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

    pub fn revoke_secret_reference(&mut self) -> Result<()> {
        self.secret_reference.revoke()?;
        self.binding_digest = self.calculate_binding_digest();
        Ok(())
    }

    fn calculate_binding_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-athena-query-result-registration/v1",
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
                ("api", self.api_revision_digest.as_str().to_owned()),
                (
                    "permission",
                    self.permission_snapshot.digest().as_str().to_owned(),
                ),
                ("consent", self.consent.digest().as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                (
                    "secret",
                    self.secret_reference.reference_digest().as_str().to_owned(),
                ),
                (
                    "secret_revoked",
                    self.secret_reference.is_revoked().to_string(),
                ),
                ("evidence", self.evidence_digest.as_str().to_owned()),
                ("revision", self.registration_revision.to_string()),
                ("status", format!("{:?}", self.status)),
            ],
        )
    }
}

impl fmt::Debug for AwsAthenaQueryResultRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsAthenaQueryResultRegistration")
            .field("id_digest", &Digest::from_text(&self.id))
            .field("plugin_version", &self.plugin_version)
            .field("version_digest", &self.version_digest)
            .field("contract_version", &self.contract_version)
            .field("contract_digest", &self.contract_digest)
            .field("provider_id", &self.provider_id)
            .field("provider_revision", &self.provider_revision)
            .field("provider_release", &self.provider_release)
            .field("provider_digest", &self.provider_digest)
            .field("api_revision_digest", &self.api_revision_digest)
            .field("permission_digest", &self.permission_digest())
            .field("consent_digest", &self.consent_digest())
            .field("scope_digest", &self.scope_digest)
            .field("secret_reference", &self.secret_reference)
            .field("evidence_digest", &self.evidence_digest)
            .field("registration_revision", &self.registration_revision)
            .field("status", &self.status)
            .field("registration_digest", &self.binding_digest)
            .finish()
    }
}

impl Serialize for AwsAthenaQueryResultRegistration {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AwsAthenaQueryResultRegistration", 18)?;
        state.serialize_field("idDigest", &Digest::from_text(&self.id))?;
        state.serialize_field("pluginVersion", &self.plugin_version)?;
        state.serialize_field("versionDigest", &self.version_digest)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("contractDigest", &self.contract_digest)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("providerRelease", &self.provider_release)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("apiRevision", &self.api_revision)?;
        state.serialize_field("apiRevisionDigest", &self.api_revision_digest)?;
        state.serialize_field("permissionSnapshotDigest", &self.permission_digest())?;
        state.serialize_field("consentDigest", &self.consent_digest())?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("secretReferenceDigest", &self.secret_reference_digest())?;
        state.serialize_field("evidenceDigest", &self.evidence_digest)?;
        state.serialize_field("registrationRevision", &self.registration_revision)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("registrationDigest", &self.binding_digest)?;
        state.end()
    }
}

pub type AwsAthenaRegistration = AwsAthenaQueryResultRegistration;

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
    pub starts_queries: bool,
    pub cancels_queries: bool,
    pub reads_s3_objects: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub outcome_adoption: bool,
    pub work_product_adoption: bool,
}

#[derive(Clone, Eq, PartialEq)]
pub struct AwsAthenaEvidenceRequest {
    scope_digest: Digest,
    query: ParameterizedAthenaQuery,
    execution_id: crate::model::QueryExecutionId,
    bounds: ResultBounds,
    include_results: bool,
    expected_provider_digest: Digest,
    expected_registration_digest: Digest,
    mission_revision: crate::model::Revision,
    observed_at: DateTime<Utc>,
    request_digest: Digest,
}

impl AwsAthenaEvidenceRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: &AwsAthenaQueryResultScope,
        query: ParameterizedAthenaQuery,
        execution_id: crate::model::QueryExecutionId,
        bounds: ResultBounds,
        include_results: bool,
        expected_provider_digest: Digest,
        expected_registration_digest: Digest,
        mission_revision: crate::model::Revision,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        query.validate_against(scope)?;
        execution_id.validate()?;
        bounds.validate()?;
        expected_provider_digest.validate()?;
        expected_registration_digest.validate()?;
        if mission_revision != scope.mission_revision() {
            return Err(AwsAthenaQueryResultError::MissionStale);
        }
        let scope_digest = scope.digest();
        let request_digest = Digest::from_parts(
            "aws-athena-athena-evidence-request/v1",
            &[
                ("scope", scope_digest.as_str().to_owned()),
                ("query", query.query_digest().as_str().to_owned()),
                ("execution", execution_id.digest().as_str().to_owned()),
                ("bounds", format!("{bounds:?}")),
                ("include_results", include_results.to_string()),
                ("provider", expected_provider_digest.as_str().to_owned()),
                (
                    "registration",
                    expected_registration_digest.as_str().to_owned(),
                ),
                ("mission_revision", mission_revision.get().to_string()),
                ("observed_at", observed_at.to_rfc3339()),
            ],
        );
        Ok(Self {
            scope_digest,
            query,
            execution_id,
            bounds,
            include_results,
            expected_provider_digest,
            expected_registration_digest,
            mission_revision,
            observed_at,
            request_digest,
        })
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn query(&self) -> &ParameterizedAthenaQuery {
        &self.query
    }

    pub fn query_digest(&self) -> &Digest {
        self.query.query_digest()
    }

    pub fn execution_id(&self) -> &crate::model::QueryExecutionId {
        &self.execution_id
    }

    pub const fn bounds(&self) -> ResultBounds {
        self.bounds
    }

    pub const fn include_results(&self) -> bool {
        self.include_results
    }

    pub fn expected_provider_digest(&self) -> &Digest {
        &self.expected_provider_digest
    }

    pub fn expected_registration_digest(&self) -> &Digest {
        &self.expected_registration_digest
    }

    pub const fn mission_revision(&self) -> crate::model::Revision {
        self.mission_revision
    }

    pub fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }
}

impl fmt::Debug for AwsAthenaEvidenceRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsAthenaEvidenceRequest")
            .field("scope_digest", &self.scope_digest)
            .field("query_digest", &self.query.query_digest())
            .field("execution_id", &self.execution_id)
            .field("bounds", &self.bounds)
            .field("include_results", &self.include_results)
            .field("expected_provider_digest", &self.expected_provider_digest)
            .field(
                "expected_registration_digest",
                &self.expected_registration_digest,
            )
            .field("mission_revision", &self.mission_revision)
            .field("observed_at", &self.observed_at)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

impl Serialize for AwsAthenaEvidenceRequest {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AwsAthenaEvidenceRequest", 9)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("queryDigest", self.query.query_digest())?;
        state.serialize_field("executionIdDigest", &self.execution_id.digest())?;
        state.serialize_field("bounds", &self.bounds)?;
        state.serialize_field("includeResults", &self.include_results)?;
        state.serialize_field("expectedProviderDigest", &self.expected_provider_digest)?;
        state.serialize_field(
            "expectedRegistrationDigest",
            &self.expected_registration_digest,
        )?;
        state.serialize_field("missionRevision", &self.mission_revision)?;
        state.serialize_field("observedAt", &self.observed_at)?;
        state.end()
    }
}

pub type AwsAthenaQueryResultRequest = AwsAthenaEvidenceRequest;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailureEvidence {
    pub operation: AwsAthenaOperation,
    pub status_code: Option<u16>,
    pub category: String,
    pub failure_digest: Digest,
}

impl FailureEvidence {
    fn from_transport(operation: AwsAthenaOperation, error: &AwsAthenaTransportError) -> Self {
        let category = match error {
            AwsAthenaTransportError::BlockedEnv => "blocked_env",
            AwsAthenaTransportError::BadRequest => "bad_request",
            AwsAthenaTransportError::Unauthorized => "unauthorized",
            AwsAthenaTransportError::Forbidden => "forbidden",
            AwsAthenaTransportError::NotFound => "not_found",
            AwsAthenaTransportError::Conflict => "conflict",
            AwsAthenaTransportError::RateLimited { .. } => "throttled",
            AwsAthenaTransportError::ServerError { .. } => "server_error",
            AwsAthenaTransportError::Timeout => "timeout",
            AwsAthenaTransportError::AccessLost => "access_loss",
            AwsAthenaTransportError::Partial => "partial",
            AwsAthenaTransportError::Expired => "expired",
            AwsAthenaTransportError::Unknown => "provider_unknown",
            AwsAthenaTransportError::InvalidResponse => "invalid_response",
            AwsAthenaTransportError::Tampered => "tampered",
            AwsAthenaTransportError::PaginationLoop => "pagination_loop",
        }
        .to_owned();
        let failure_digest = Digest::from_parts(
            "aws-athena-failure/v1",
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
pub struct AwsAthenaQueryResultProposal {
    pub service_id: String,
    pub consumer_id: String,
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub account_digest: Digest,
    pub region_digest: Digest,
    pub workgroup_digest: Digest,
    pub catalog_digest: Digest,
    pub database_digest: Digest,
    pub mission: MissionProjection,
    pub project: ProjectProjection,
    pub work_product: WorkProductProjection,
    pub query_digest: Digest,
    pub execution_id_digest: Digest,
    pub state: AthenaQueryResultStatus,
    pub execution_state: Option<AthenaExecutionState>,
    pub pages: u16,
    pub pages_complete: bool,
    pub truncated: bool,
    pub execution: Option<QueryExecutionMetadata>,
    pub results: Option<QueryResultsProjection>,
    pub request_receipts: Vec<RequestReceipt>,
    pub cost_receipts: Vec<CostReceipt>,
    pub failure: Option<FailureEvidence>,
    pub evidence: EvidenceDigests,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub proposal_digest: Digest,
}

impl AwsAthenaQueryResultProposal {
    #[allow(clippy::too_many_arguments)]
    fn new(
        registration: &AwsAthenaQueryResultRegistration,
        provider: &AwsAthenaProviderDefinition,
        request: &AwsAthenaEvidenceRequest,
        state: AthenaQueryResultStatus,
        execution_state: Option<AthenaExecutionState>,
        pages: u16,
        pages_complete: bool,
        truncated: bool,
        execution: Option<QueryExecutionMetadata>,
        results: Option<QueryResultsProjection>,
        request_receipts: Vec<RequestReceipt>,
        cost_receipts: Vec<CostReceipt>,
        failure: Option<FailureEvidence>,
        provenance: TransportProvenance,
    ) -> Self {
        let execution_digest = execution.as_ref().map(|value| value.digest().clone());
        let results_digest = results.as_ref().map(|value| value.shape_digest.clone());
        let evidence_without_digest = Digest::from_parts(
            "aws-athena-evidence/v1",
            &[
                (
                    "plugin",
                    Digest::from_text(PLUGIN_VERSION).as_str().to_owned(),
                ),
                ("contract", registration.contract_digest.as_str().to_owned()),
                (
                    "evidence_contract",
                    registration.evidence_digest.as_str().to_owned(),
                ),
                ("provider", provider.provider_digest.as_str().to_owned()),
                ("api", Digest::from_text(API_REVISION).as_str().to_owned()),
                (
                    "permission",
                    registration.permission_digest().as_str().to_owned(),
                ),
                ("consent", registration.consent_digest().as_str().to_owned()),
                ("scope", registration.scope_digest.as_str().to_owned()),
                ("query", request.query_digest().as_str().to_owned()),
                (
                    "execution",
                    execution_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "results",
                    results_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "requests",
                    request_receipts
                        .iter()
                        .map(|receipt| receipt.receipt_digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "costs",
                    cost_receipts
                        .iter()
                        .map(|receipt| receipt.cost_digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                ("state", state.as_str().to_owned()),
            ],
        );
        let evidence = EvidenceDigests {
            plugin_version_digest: Digest::from_text(PLUGIN_VERSION),
            contract_digest: registration.contract_digest.clone(),
            evidence_contract_digest: registration.evidence_digest.clone(),
            provider_digest: provider.provider_digest.clone(),
            api_revision_digest: Digest::from_text(API_REVISION),
            permission_digest: registration.permission_digest(),
            consent_digest: registration.consent_digest(),
            scope_digest: registration.scope_digest.clone(),
            query_digest: request.query_digest().clone(),
            execution_digest,
            results_digest,
            evidence_digest: evidence_without_digest,
        };
        let mut proposal = Self {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            registration_digest: registration.registration_digest().clone(),
            scope_digest: registration.scope_digest.clone(),
            account_digest: registration.scope.account().digest(),
            region_digest: registration.scope.region().digest(),
            workgroup_digest: registration.scope.workgroup().digest(),
            catalog_digest: registration.scope.catalog().digest(),
            database_digest: registration.scope.database().digest(),
            mission: mission_projection(&registration.scope),
            project: project_projection(&registration.scope),
            work_product: work_product_projection(&registration.scope),
            query_digest: request.query_digest().clone(),
            execution_id_digest: request.execution_id().digest(),
            state,
            execution_state,
            pages,
            pages_complete,
            truncated,
            execution,
            results,
            request_receipts,
            cost_receipts,
            failure,
            evidence,
            provenance,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            proposal_digest: Digest::from_text("unsealed-athena-proposal"),
        };
        proposal.proposal_digest = proposal.calculate_digest();
        proposal
    }

    pub fn status(&self) -> AthenaQueryResultStatus {
        self.state
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
            || self.provenance.is_native()
            || self.proposal_digest != self.calculate_digest()
        {
            return Err(AwsAthenaQueryResultError::EvidenceTampered);
        }
        for receipt in &self.request_receipts {
            receipt.validate()?;
        }
        for receipt in &self.cost_receipts {
            receipt.validate()?;
        }
        if let Some(execution) = &self.execution {
            execution.validate_against_digest(&self.scope_digest, &self.query_digest)?;
        }
        if let Some(results) = &self.results {
            results.validate()?;
        }
        if self.evidence.scope_digest != self.scope_digest
            || self.evidence.query_digest != self.query_digest
            || self.evidence.evidence_digest != self.calculate_evidence_digest()
        {
            return Err(AwsAthenaQueryResultError::EvidenceTampered);
        }
        Ok(())
    }

    fn calculate_evidence_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-athena-evidence/v1",
            &[
                (
                    "plugin",
                    self.evidence.plugin_version_digest.as_str().to_owned(),
                ),
                (
                    "contract",
                    self.evidence.contract_digest.as_str().to_owned(),
                ),
                (
                    "evidence_contract",
                    self.evidence.evidence_contract_digest.as_str().to_owned(),
                ),
                (
                    "provider",
                    self.evidence.provider_digest.as_str().to_owned(),
                ),
                ("api", self.evidence.api_revision_digest.as_str().to_owned()),
                (
                    "permission",
                    self.evidence.permission_digest.as_str().to_owned(),
                ),
                ("consent", self.evidence.consent_digest.as_str().to_owned()),
                ("scope", self.evidence.scope_digest.as_str().to_owned()),
                ("query", self.evidence.query_digest.as_str().to_owned()),
                (
                    "execution",
                    self.evidence
                        .execution_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "results",
                    self.evidence
                        .results_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "requests",
                    self.request_receipts
                        .iter()
                        .map(|receipt| receipt.receipt_digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "costs",
                    self.cost_receipts
                        .iter()
                        .map(|receipt| receipt.cost_digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                ("state", self.state.as_str().to_owned()),
            ],
        )
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-athena-query-result-proposal/v1",
            &[
                ("service", self.service_id.clone()),
                ("consumer", self.consumer_id.clone()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("query", self.query_digest.as_str().to_owned()),
                ("execution", self.execution_id_digest.as_str().to_owned()),
                ("state", self.state.as_str().to_owned()),
                (
                    "execution_state",
                    self.execution_state
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                ("pages", self.pages.to_string()),
                ("pages_complete", self.pages_complete.to_string()),
                ("truncated", self.truncated.to_string()),
                (
                    "execution_digest",
                    self.evidence
                        .execution_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "results_digest",
                    self.evidence
                        .results_digest
                        .as_ref()
                        .map_or_else(String::new, |value| value.as_str().to_owned()),
                ),
                (
                    "evidence",
                    self.evidence.evidence_digest.as_str().to_owned(),
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

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFailure {
    RegistrationInactive,
    RegistrationDigestMismatch,
    ProviderDigestMismatch,
    PermissionDigestMismatch,
    ConsentDigestMismatch,
    ScopeDigestMismatch,
    QueryDigestMismatch,
    MissionRevisionMismatch,
    TamperedEvidence,
    PartialEvidence,
    AccessLoss,
    ProviderUnknown,
    Revoked,
    Stale,
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
            "aws-athena-verification-report/v1",
            &[
                ("valid", valid.to_string()),
                ("review_eligible", review_eligible.to_string()),
                (
                    "failures",
                    failures
                        .iter()
                        .map(|failure| format!("{failure:?}"))
                        .collect::<Vec<_>>()
                        .join(","),
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

pub struct AwsAthenaQueryResultService<T: crate::provider::AwsAthenaTransport> {
    registration: AwsAthenaQueryResultRegistration,
    provider: AwsAthenaProvider<T>,
}

impl<T: crate::provider::AwsAthenaTransport> fmt::Debug for AwsAthenaQueryResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsAthenaQueryResultService")
            .field("registration", &self.registration)
            .field("provider", &self.provider)
            .finish()
    }
}

impl<T: crate::provider::AwsAthenaTransport> AwsAthenaQueryResultService<T> {
    pub fn new(
        scope: AwsAthenaQueryResultScope,
        secret_reference: SecretReference,
        consent: ConsentScope,
        provider: AwsAthenaProvider<T>,
        registration_time: DateTime<Utc>,
    ) -> Result<Self> {
        Self::with_registration(
            "aws-athena-query-result-registration",
            scope,
            secret_reference,
            PermissionSnapshot::new(
                1,
                [
                    "athena:GetQueryExecution",
                    "athena:GetQueryResults",
                    "mission.scope",
                    "project.scope",
                    "work_product.scope",
                ],
            )?,
            consent,
            provider,
            1,
            registration_time,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_registration(
        registration_id: impl Into<String>,
        scope: AwsAthenaQueryResultScope,
        secret_reference: SecretReference,
        permission_snapshot: PermissionSnapshot,
        consent: ConsentScope,
        provider: AwsAthenaProvider<T>,
        registration_revision: u64,
        _registration_time: DateTime<Utc>,
    ) -> Result<Self> {
        let registration = AwsAthenaQueryResultRegistration::new(
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
                AwsAthenaOperation::GetQueryExecution.as_str().to_owned(),
                AwsAthenaOperation::GetQueryResults.as_str().to_owned(),
            ],
            permissions: crate::LAYER1_PERMISSIONS
                .iter()
                .map(|permission| (*permission).to_owned())
                .collect(),
            read_only: true,
            proposal_only: true,
            starts_queries: false,
            cancels_queries: false,
            reads_s3_objects: false,
            connected: false,
            native: false,
            first_party: false,
            outcome_adoption: false,
            work_product_adoption: false,
        }
    }

    pub fn scope(&self) -> &AwsAthenaQueryResultScope {
        self.registration.scope()
    }

    pub fn registration(&self) -> &AwsAthenaQueryResultRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut AwsAthenaQueryResultRegistration {
        &mut self.registration
    }

    pub fn provider(&self) -> &AwsAthenaProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AwsAthenaProvider<T> {
        &mut self.provider
    }

    pub fn request(
        &self,
        query: ParameterizedAthenaQuery,
        execution_id: crate::model::QueryExecutionId,
        bounds: ResultBounds,
        include_results: bool,
        observed_at: DateTime<Utc>,
    ) -> Result<AwsAthenaEvidenceRequest> {
        AwsAthenaEvidenceRequest::new(
            self.scope(),
            query,
            execution_id,
            bounds,
            include_results,
            self.provider.definition().provider_digest.clone(),
            self.registration.registration_digest().clone(),
            self.scope().mission_revision(),
            observed_at,
        )
    }

    pub fn default_query(
        &self,
    ) -> std::result::Result<ParameterizedAthenaQuery, crate::query::QueryCompileError> {
        let bounds = ResultBounds::new(25, 1024 * 1024, 4, 25)
            .map_err(|_| crate::query::QueryCompileError::LimitExceedsBound)?;
        ParameterizedAthenaQuery::compile(
            self.scope(),
            format!(
                "SELECT * FROM {}.{}.{} WHERE fixture_id = :fixture LIMIT 1",
                self.scope().catalog().as_str(),
                self.scope().database().as_str(),
                self.scope()
                    .allowlisted_tables()
                    .iter()
                    .next()
                    .expect("scope has a table")
                    .as_str()
            ),
            [crate::query::QueryParameter::from_public_value(
                "fixture",
                crate::query::QueryParameterType::Integer,
                b"1",
            )?],
            bounds,
        )
    }

    pub fn default_request(&self, observed_at: DateTime<Utc>) -> Result<AwsAthenaEvidenceRequest> {
        let query = self
            .default_query()
            .map_err(|_| AwsAthenaQueryResultError::InvalidRequest)?;
        self.request(
            query,
            crate::model::QueryExecutionId::new("athena-fixture-execution")?,
            ResultBounds::new(25, 1024 * 1024, 4, 25)?,
            true,
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

    pub fn consumer(
        &self,
    ) -> std::result::Result<MissionAwsAthenaConsumer, crate::consumer::ConsumerError> {
        MissionAwsAthenaConsumer::new(self.scope().clone(), self.registration.clone())
    }

    pub fn verify(&self, proposal: &AwsAthenaQueryResultProposal) -> VerificationReport {
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
        if proposal.query_digest != proposal.evidence.query_digest {
            failures.push(VerificationFailure::QueryDigestMismatch);
        }
        if proposal.mission.revision != self.scope().mission_revision() {
            failures.push(VerificationFailure::MissionRevisionMismatch);
        }
        if proposal.validate_integrity().is_err() {
            failures.push(VerificationFailure::TamperedEvidence);
        }
        match proposal.state {
            AthenaQueryResultStatus::Partial => failures.push(VerificationFailure::PartialEvidence),
            AthenaQueryResultStatus::AccessLost => failures.push(VerificationFailure::AccessLoss),
            AthenaQueryResultStatus::ProviderUnknown => {
                failures.push(VerificationFailure::ProviderUnknown);
            }
            AthenaQueryResultStatus::Tampered => {
                failures.push(VerificationFailure::TamperedEvidence);
            }
            AthenaQueryResultStatus::Revoked => failures.push(VerificationFailure::Revoked),
            AthenaQueryResultStatus::Stale => failures.push(VerificationFailure::Stale),
            AthenaQueryResultStatus::Queued
            | AthenaQueryResultStatus::Running
            | AthenaQueryResultStatus::Succeeded
            | AthenaQueryResultStatus::Failed
            | AthenaQueryResultStatus::Cancelled
            | AthenaQueryResultStatus::Expired => {}
        }
        failures.sort_unstable();
        failures.dedup();
        let valid = failures.is_empty();
        VerificationReport::new(
            valid,
            valid && proposal.state == AthenaQueryResultStatus::Succeeded,
            failures,
        )
    }

    pub fn propose(
        &mut self,
        request: AwsAthenaEvidenceRequest,
    ) -> Result<AwsAthenaQueryResultProposal> {
        self.registration.validate()?;
        if !self.registration.is_active() {
            return Err(AwsAthenaQueryResultError::RegistrationInactive);
        }
        if self.registration.secret_reference().is_revoked() {
            return Err(AwsAthenaQueryResultError::SecretRevoked);
        }
        if request.scope_digest != *self.registration.scope_digest()
            || request.expected_provider_digest != self.provider.definition().provider_digest
            || request.expected_registration_digest != *self.registration.registration_digest()
        {
            return Err(AwsAthenaQueryResultError::ScopeMismatch);
        }
        if request.mission_revision != self.scope().mission_revision() {
            return Err(AwsAthenaQueryResultError::MissionStale);
        }
        request.query.validate_against(self.scope())?;
        if self.registration.consent().is_revoked() {
            return Err(AwsAthenaQueryResultError::ConsentRevoked);
        }
        if !self
            .registration
            .consent()
            .is_active_at(request.observed_at)
        {
            return Err(AwsAthenaQueryResultError::ConsentExpired);
        }

        let execution_request = GetQueryExecutionRequest::new(
            self.scope(),
            request.query_digest().clone(),
            request.execution_id.clone(),
        )?;
        let execution_response = match self.provider.get_query_execution(&execution_request) {
            Ok(response) => response,
            Err(error) => {
                return Ok(self.failure_proposal(
                    &request,
                    AthenaQueryResultStatus::from_transport_error(&error),
                    None,
                    None,
                    0,
                    false,
                    false,
                    Vec::new(),
                    Vec::new(),
                    Some(FailureEvidence::from_transport(
                        AwsAthenaOperation::GetQueryExecution,
                        &error,
                    )),
                ));
            }
        };
        let execution = execution_response.execution.clone();
        if execution
            .validate_against(self.scope(), request.query_digest())
            .is_err()
        {
            return Ok(self.failure_proposal(
                &request,
                AthenaQueryResultStatus::Tampered,
                Some(execution),
                None,
                0,
                false,
                false,
                Vec::new(),
                Vec::new(),
                Some(FailureEvidence {
                    operation: AwsAthenaOperation::GetQueryExecution,
                    status_code: None,
                    category: "execution_scope_drift".to_owned(),
                    failure_digest: Digest::from_text("athena-execution-scope-drift"),
                }),
            ));
        }
        let execution_state = execution.state;
        let mut request_receipts = vec![RequestReceipt::new(
            AwsAthenaOperation::GetQueryExecution.as_str(),
            execution_request.request_digest().clone(),
            request.scope_digest.clone(),
            request.query_digest().clone(),
            request.execution_id.digest(),
            None,
            execution_response.response_bytes,
        )?];
        let mut cost_receipts = vec![CostReceipt::new(
            AwsAthenaOperation::GetQueryExecution.as_str(),
            execution_response.response_bytes,
        )?];

        let mut state = if execution.expired {
            AthenaQueryResultStatus::Expired
        } else {
            match execution_state {
                AthenaExecutionState::Queued => AthenaQueryResultStatus::Queued,
                AthenaExecutionState::Running => AthenaQueryResultStatus::Running,
                AthenaExecutionState::Succeeded => AthenaQueryResultStatus::Succeeded,
                AthenaExecutionState::Failed => AthenaQueryResultStatus::Failed,
                AthenaExecutionState::Cancelled => AthenaQueryResultStatus::Cancelled,
                AthenaExecutionState::Unknown => AthenaQueryResultStatus::ProviderUnknown,
            }
        };
        let mut results = None;
        let mut pages = 0;
        let mut pages_complete = true;
        let mut truncated = false;
        let mut failure = None;

        if state == AthenaQueryResultStatus::Succeeded
            && request.include_results
            && self.registration.permission_snapshot().allows_results()
        {
            let mut next_token: Option<OpaquePageToken> = None;
            let mut seen_tokens = BTreeSet::new();
            let mut total_bytes = 0_u64;
            let mut all_rows = Vec::new();
            let mut all_columns = None;
            loop {
                if pages >= request.bounds.max_pages() {
                    pages_complete = false;
                    truncated = true;
                    state = AthenaQueryResultStatus::Partial;
                    break;
                }
                let page_request = if let Ok(value) = GetQueryResultsRequest::new(
                    self.scope(),
                    request.query_digest().clone(),
                    request.execution_id.clone(),
                    request.bounds,
                    next_token.clone(),
                ) {
                    value
                } else {
                    state = AthenaQueryResultStatus::Tampered;
                    failure = Some(FailureEvidence {
                        operation: AwsAthenaOperation::GetQueryResults,
                        status_code: None,
                        category: "page_token_mismatch".to_owned(),
                        failure_digest: Digest::from_text("athena-page-token-mismatch"),
                    });
                    break;
                };
                let response = match self.provider.get_query_results(&page_request) {
                    Ok(response) => response,
                    Err(error) => {
                        state = AthenaQueryResultStatus::from_transport_error(&error);
                        failure = Some(FailureEvidence::from_transport(
                            AwsAthenaOperation::GetQueryResults,
                            &error,
                        ));
                        pages_complete = false;
                        break;
                    }
                };
                pages += 1;
                total_bytes = total_bytes.saturating_add(response.response_bytes);
                request_receipts.push(RequestReceipt::new(
                    AwsAthenaOperation::GetQueryResults.as_str(),
                    page_request.request_digest().clone(),
                    request.scope_digest.clone(),
                    request.query_digest().clone(),
                    request.execution_id.digest(),
                    page_request
                        .page_token()
                        .map(|token| token.token_digest().clone()),
                    response.response_bytes,
                )?);
                cost_receipts.push(CostReceipt::new(
                    AwsAthenaOperation::GetQueryResults.as_str(),
                    response.response_bytes,
                )?);
                if total_bytes > request.bounds.max_bytes() {
                    state = AthenaQueryResultStatus::Partial;
                    truncated = true;
                    pages_complete = false;
                    break;
                }
                if all_columns.is_none() {
                    all_columns = Some(response.projection.columns.clone());
                }
                let remaining = request
                    .bounds
                    .max_rows()
                    .saturating_sub(u32::try_from(all_rows.len()).unwrap_or(u32::MAX));
                if u32::try_from(response.projection.rows.len()).unwrap_or(u32::MAX) > remaining {
                    all_rows.extend(
                        response
                            .projection
                            .rows
                            .into_iter()
                            .take(remaining as usize),
                    );
                    state = AthenaQueryResultStatus::Partial;
                    truncated = true;
                    pages_complete = false;
                    break;
                }
                all_rows.extend(response.projection.rows);
                if response.truncated {
                    state = AthenaQueryResultStatus::Partial;
                    truncated = true;
                }
                if response.complete {
                    pages_complete = true;
                    break;
                }
                let Some(token) = response.next_page_token else {
                    state = AthenaQueryResultStatus::Partial;
                    pages_complete = false;
                    break;
                };
                if !seen_tokens.insert(token.token_digest().clone()) {
                    state = AthenaQueryResultStatus::Tampered;
                    failure = Some(FailureEvidence {
                        operation: AwsAthenaOperation::GetQueryResults,
                        status_code: None,
                        category: "pagination_loop".to_owned(),
                        failure_digest: Digest::from_text("athena-pagination-loop"),
                    });
                    pages_complete = false;
                    break;
                }
                next_token = Some(token);
            }
            if !all_rows.is_empty() || all_columns.is_some() {
                results = Some(QueryResultsProjection::new(
                    all_columns.unwrap_or_default(),
                    all_rows,
                )?);
            }
        }

        if state == AthenaQueryResultStatus::Succeeded
            && execution_state == AthenaExecutionState::Succeeded
        {
            pages_complete = !request.include_results
                || self.registration.permission_snapshot().allows_results();
        }
        Ok(AwsAthenaQueryResultProposal::new(
            &self.registration,
            self.provider.definition(),
            &request,
            state,
            Some(execution_state),
            pages,
            pages_complete,
            truncated,
            Some(execution),
            results,
            request_receipts,
            cost_receipts,
            failure,
            self.provider.provenance(),
        ))
    }

    fn failure_proposal(
        &self,
        request: &AwsAthenaEvidenceRequest,
        state: AthenaQueryResultStatus,
        execution: Option<QueryExecutionMetadata>,
        results: Option<QueryResultsProjection>,
        pages: u16,
        pages_complete: bool,
        truncated: bool,
        request_receipts: Vec<RequestReceipt>,
        cost_receipts: Vec<CostReceipt>,
        failure: Option<FailureEvidence>,
    ) -> AwsAthenaQueryResultProposal {
        AwsAthenaQueryResultProposal::new(
            &self.registration,
            self.provider.definition(),
            request,
            state,
            execution.as_ref().map(|value| value.state),
            pages,
            pages_complete,
            truncated,
            execution,
            results,
            request_receipts,
            cost_receipts,
            failure,
            self.provider.provenance(),
        )
    }
}

impl AthenaQueryResultStatus {
    fn from_transport_error(error: &AwsAthenaTransportError) -> Self {
        match error {
            AwsAthenaTransportError::Unauthorized
            | AwsAthenaTransportError::Forbidden
            | AwsAthenaTransportError::AccessLost => Self::AccessLost,
            AwsAthenaTransportError::Partial => Self::Partial,
            AwsAthenaTransportError::Expired => Self::Expired,
            AwsAthenaTransportError::Tampered
            | AwsAthenaTransportError::InvalidResponse
            | AwsAthenaTransportError::PaginationLoop => Self::Tampered,
            AwsAthenaTransportError::BlockedEnv
            | AwsAthenaTransportError::BadRequest
            | AwsAthenaTransportError::NotFound
            | AwsAthenaTransportError::Conflict
            | AwsAthenaTransportError::RateLimited { .. }
            | AwsAthenaTransportError::ServerError { .. }
            | AwsAthenaTransportError::Timeout
            | AwsAthenaTransportError::Unknown => Self::ProviderUnknown,
        }
    }
}

fn valid_registration_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= crate::MAX_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}
