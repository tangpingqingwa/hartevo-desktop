use std::{collections::VecDeque, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    GCP_RECOMMENDER_RESULT_CONTRACT_VERSION, GCP_RECOMMENDER_RESULT_PROVIDER_ID,
    GCP_RECOMMENDER_RESULT_PROVIDER_VERSION, GCP_RECOMMENDER_RESULT_SCHEMA_VERSION,
    model::{
        Digest, GcpParent, GcpRecommenderQuery, GcpRecommenderRecord, GcpRecommenderScope,
        GcpResultKind, Location, MissionId, ModelError, OpaquePageToken, PermissionFence,
        ProjectId, ProviderErrorKind, ProviderResponseFence, ResultFilters, ResultId, Revision,
        SecretReference, WorkProductId,
    },
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProvenance {
    Fixture,
    Recording,
    Loopback,
    BlockedEnv,
}

impl ProviderProvenance {
    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_connected(self) -> bool {
        false
    }

    pub const fn is_first_party(self) -> bool {
        false
    }

    pub const fn is_blocked_env(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("provider version is empty")]
    EmptyVersion,
    #[error("Layer 1 cannot register a native, connected, or first-party provider")]
    NativeProviderForbidden,
    #[error("transport provenance does not match the provider definition")]
    ProvenanceMismatch,
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpRecommenderProviderDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub provider_id: crate::ProviderId,
    pub provider_version: String,
    pub api_version: String,
    pub capability_digest: Digest,
    pub provenance: ProviderProvenance,
    pub recommendations_list: bool,
    pub recommendations_get: bool,
    pub insights_list: bool,
    pub insights_get: bool,
    pub live_execution: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
}

pub type GcpProviderDefinition = GcpRecommenderProviderDefinition;

impl GcpRecommenderProviderDefinition {
    pub fn layer1(provenance: ProviderProvenance) -> Result<Self, ProviderDefinitionError> {
        Self::new(GCP_RECOMMENDER_RESULT_PROVIDER_VERSION, provenance)
    }

    pub fn new(
        provider_version: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        let provider_version = provider_version.into();
        if provider_version.is_empty() {
            return Err(ProviderDefinitionError::EmptyVersion);
        }
        if provenance.is_native() || provenance.is_connected() || provenance.is_first_party() {
            return Err(ProviderDefinitionError::NativeProviderForbidden);
        }
        let provider_id = crate::ProviderId::new(GCP_RECOMMENDER_RESULT_PROVIDER_ID)?;
        let capability_digest = Digest::from_fields(
            "gcp-recommender-provider-capability/v1",
            &[
                GCP_RECOMMENDER_RESULT_SCHEMA_VERSION.to_owned(),
                GCP_RECOMMENDER_RESULT_CONTRACT_VERSION.to_owned(),
                GCP_RECOMMENDER_RESULT_PROVIDER_ID.to_owned(),
                provider_version.clone(),
                "v1".to_owned(),
                format!("{provenance:?}"),
                "recommendations.list".to_owned(),
                "recommendations.get".to_owned(),
                "insights.list".to_owned(),
                "insights.get".to_owned(),
                "live_execution=false".to_owned(),
            ],
        );
        Ok(Self {
            schema_version: GCP_RECOMMENDER_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: GCP_RECOMMENDER_RESULT_CONTRACT_VERSION.to_owned(),
            provider_id,
            provider_version,
            api_version: "v1".to_owned(),
            capability_digest,
            provenance,
            recommendations_list: true,
            recommendations_get: true,
            insights_list: true,
            insights_get: true,
            live_execution: false,
            native: false,
            connected: false,
            first_party: false,
        })
    }

    pub fn provider_digest(&self) -> Digest {
        Digest::from_fields(
            "gcp-recommender-provider-definition/v1",
            &[
                self.schema_version.clone(),
                self.contract_version.clone(),
                self.provider_id.as_str().to_owned(),
                self.provider_version.clone(),
                self.api_version.clone(),
                self.capability_digest.as_str().to_owned(),
                format!("{:?}", self.provenance),
                self.recommendations_list.to_string(),
                self.recommendations_get.to_string(),
                self.insights_list.to_string(),
                self.insights_get.to_string(),
                self.live_execution.to_string(),
                self.native.to_string(),
                self.connected.to_string(),
                self.first_party.to_string(),
            ],
        )
    }

    pub fn validate(&self) -> Result<(), ProviderDefinitionError> {
        let expected_capability = Self::new(self.provider_version.clone(), self.provenance)?;
        if self.schema_version != GCP_RECOMMENDER_RESULT_SCHEMA_VERSION
            || self.contract_version != GCP_RECOMMENDER_RESULT_CONTRACT_VERSION
            || self.provider_id.as_str() != GCP_RECOMMENDER_RESULT_PROVIDER_ID
            || self.provider_version.is_empty()
            || self.api_version != "v1"
            || self.capability_digest != expected_capability.capability_digest
            || !self.recommendations_list
            || !self.recommendations_get
            || !self.insights_list
            || !self.insights_get
            || self.live_execution
            || self.native
            || self.connected
            || self.first_party
            || self.provenance.is_native()
            || self.provenance.is_connected()
            || self.provenance.is_first_party()
        {
            Err(ProviderDefinitionError::NativeProviderForbidden)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("GCP Recommender provider transport returned {kind:?}")]
pub struct TransportError {
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub retryable: bool,
    pub blocked_env: bool,
    diagnostic_digest: Digest,
}

impl TransportError {
    pub fn new(
        kind: ProviderErrorKind,
        status_code: Option<u16>,
        diagnostic: impl AsRef<[u8]>,
    ) -> Self {
        let retryable = matches!(
            kind,
            ProviderErrorKind::RateLimited
                | ProviderErrorKind::ServerFailure
                | ProviderErrorKind::Timeout
        );
        Self {
            kind,
            status_code,
            retryable,
            blocked_env: kind == ProviderErrorKind::BlockedEnv,
            diagnostic_digest: Digest::from_text(diagnostic),
        }
    }

    pub fn bad_request() -> Self {
        Self::new(ProviderErrorKind::BadRequest, Some(400), "bad-request")
    }

    pub fn unauthenticated() -> Self {
        Self::new(
            ProviderErrorKind::Unauthenticated,
            Some(401),
            "unauthenticated",
        )
    }

    pub fn access_denied() -> Self {
        Self::new(
            ProviderErrorKind::PermissionDenied,
            Some(403),
            "permission-denied",
        )
    }

    pub fn not_found() -> Self {
        Self::new(ProviderErrorKind::NotFound, Some(404), "not-found")
    }

    pub fn conflict() -> Self {
        Self::new(ProviderErrorKind::Conflict, Some(409), "conflict")
    }

    pub fn rate_limited() -> Self {
        Self::new(ProviderErrorKind::RateLimited, Some(429), "rate-limited")
    }

    pub fn server_failure(status_code: u16) -> Self {
        Self::new(
            ProviderErrorKind::ServerFailure,
            Some(status_code),
            "server-failure",
        )
    }

    pub fn timeout() -> Self {
        Self::new(ProviderErrorKind::Timeout, None, "timeout")
    }

    pub fn blocked_env() -> Self {
        Self::new(ProviderErrorKind::BlockedEnv, None, "BLOCKED_ENV")
    }

    pub fn diagnostic_digest(&self) -> &Digest {
        &self.diagnostic_digest
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpRecommenderListRequest {
    pub parent: GcpParent,
    pub location: Location,
    pub result_kind: GcpResultKind,
    pub filters: ResultFilters,
    pub query_digest: Digest,
    pub filter_digest: Digest,
    pub scope_digest: Digest,
    pub page_size: u32,
    pub page_number: u8,
    #[serde(skip)]
    pub page_token: Option<OpaquePageToken>,
    pub page_token_digest: Option<Digest>,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub work_product_id: WorkProductId,
    pub project_revision: Revision,
    pub mission_revision: Revision,
    pub work_product_revision: Revision,
    pub secret_reference_digest: Digest,
    pub credential_revision: Revision,
    pub api_version: String,
    pub request_digest: Digest,
}

impl fmt::Debug for GcpRecommenderListRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GcpRecommenderListRequest")
            .field("parent", &self.parent)
            .field("location", &self.location)
            .field("result_kind", &self.result_kind)
            .field("filters", &self.filters)
            .field("query_digest", &self.query_digest)
            .field("filter_digest", &self.filter_digest)
            .field("scope_digest", &self.scope_digest)
            .field("page_size", &self.page_size)
            .field("page_number", &self.page_number)
            .field("page_token_digest", &self.page_token_digest)
            .field("permission_digest", &self.permission_digest)
            .field("consent_digest", &self.consent_digest)
            .field("project_revision", &self.project_revision)
            .field("mission_revision", &self.mission_revision)
            .field("work_product_revision", &self.work_product_revision)
            .field("credential_revision", &self.credential_revision)
            .field("api_version", &self.api_version)
            .field("request_digest", &self.request_digest)
            .finish_non_exhaustive()
    }
}

impl GcpRecommenderListRequest {
    pub fn from_scope(
        scope: &GcpRecommenderScope,
        query: &GcpRecommenderQuery,
        secret: &SecretReference,
        page_number: u8,
        page_token: Option<OpaquePageToken>,
    ) -> Self {
        let page_token_digest = page_token.as_ref().map(OpaquePageToken::digest);
        let mut request = Self {
            parent: scope.parent().clone(),
            location: scope.location().clone(),
            result_kind: scope.result_kind().clone(),
            filters: query.filters().clone(),
            query_digest: query.digest(),
            filter_digest: query.filters().digest(),
            scope_digest: scope.digest(),
            page_size: query.page_size(),
            page_number,
            page_token,
            page_token_digest,
            permission_digest: scope.permission().digest(),
            consent_digest: scope.consent().digest(),
            project_id: scope.project().project_id().clone(),
            mission_id: scope.mission().mission_id().clone(),
            work_product_id: scope.work_product().work_product_id().clone(),
            project_revision: scope.project().revision(),
            mission_revision: scope.mission().revision(),
            work_product_revision: scope.work_product().revision(),
            secret_reference_digest: secret.digest(),
            credential_revision: secret.credential_revision(),
            api_version: "v1".to_owned(),
            request_digest: Digest::from_text("request-placeholder"),
        };
        request.request_digest = request.digest();
        request
    }

    pub fn page_token_digest(&self) -> Option<Digest> {
        self.page_token_digest.clone()
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "gcp-recommender-list-request/v1",
            &[
                self.parent.resource_name(),
                self.location.as_str().to_owned(),
                format!("{:?}", self.result_kind),
                self.query_digest.as_str().to_owned(),
                self.filter_digest.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.page_size.to_string(),
                self.page_number.to_string(),
                self.page_token_digest
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), |digest| digest.as_str().to_owned()),
                self.permission_digest.as_str().to_owned(),
                self.consent_digest.as_str().to_owned(),
                self.project_id.as_str().to_owned(),
                self.mission_id.as_str().to_owned(),
                self.work_product_id.as_str().to_owned(),
                self.project_revision.get().to_string(),
                self.mission_revision.get().to_string(),
                self.work_product_revision.get().to_string(),
                self.secret_reference_digest.as_str().to_owned(),
                self.credential_revision.get().to_string(),
                self.api_version.clone(),
            ],
        )
    }

    pub fn fence(&self) -> PermissionFence {
        PermissionFence {
            scope_digest: self.scope_digest.clone(),
            permission_digest: self.permission_digest.clone(),
            consent_digest: self.consent_digest.clone(),
            project_revision: self.project_revision,
            mission_revision: self.mission_revision,
            work_product_revision: self.work_product_revision,
        }
    }

    pub fn is_allowlisted(&self) -> bool {
        self.api_version == "v1"
            && self.page_size > 0
            && self.page_size <= 100
            && self.filters.validate().is_ok()
            && self.filter_digest == self.filters.digest()
            && self.request_digest == self.digest()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpRecommenderGetRequest {
    pub parent: GcpParent,
    pub location: Location,
    pub result_kind: GcpResultKind,
    pub result_id: ResultId,
    pub filters: ResultFilters,
    pub query_digest: Digest,
    pub filter_digest: Digest,
    pub scope_digest: Digest,
    pub expected_etag_digest: Option<Digest>,
    pub expected_revision: Option<Revision>,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub work_product_id: WorkProductId,
    pub project_revision: Revision,
    pub mission_revision: Revision,
    pub work_product_revision: Revision,
    pub secret_reference_digest: Digest,
    pub credential_revision: Revision,
    pub api_version: String,
    pub request_digest: Digest,
}

impl GcpRecommenderGetRequest {
    pub fn from_scope(
        scope: &GcpRecommenderScope,
        query: &GcpRecommenderQuery,
        secret: &SecretReference,
        result_id: ResultId,
        expected: Option<crate::ResultVersionFence>,
    ) -> Self {
        let mut request = Self {
            parent: scope.parent().clone(),
            location: scope.location().clone(),
            result_kind: scope.result_kind().clone(),
            result_id,
            filters: query.filters().clone(),
            query_digest: query.digest(),
            filter_digest: query.filters().digest(),
            scope_digest: scope.digest(),
            expected_etag_digest: expected.as_ref().map(|fence| fence.etag_digest.clone()),
            expected_revision: expected.map(|fence| fence.revision),
            permission_digest: scope.permission().digest(),
            consent_digest: scope.consent().digest(),
            project_id: scope.project().project_id().clone(),
            mission_id: scope.mission().mission_id().clone(),
            work_product_id: scope.work_product().work_product_id().clone(),
            project_revision: scope.project().revision(),
            mission_revision: scope.mission().revision(),
            work_product_revision: scope.work_product().revision(),
            secret_reference_digest: secret.digest(),
            credential_revision: secret.credential_revision(),
            api_version: "v1".to_owned(),
            request_digest: Digest::from_text("request-placeholder"),
        };
        request.request_digest = request.digest();
        request
    }

    pub fn digest(&self) -> Digest {
        Digest::from_fields(
            "gcp-recommender-get-request/v1",
            &[
                self.parent.resource_name(),
                self.location.as_str().to_owned(),
                format!("{:?}", self.result_kind),
                self.result_id.as_str().to_owned(),
                self.query_digest.as_str().to_owned(),
                self.filter_digest.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.expected_etag_digest
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), |digest| digest.as_str().to_owned()),
                self.expected_revision
                    .map_or_else(|| "none".to_owned(), |revision| revision.get().to_string()),
                self.permission_digest.as_str().to_owned(),
                self.consent_digest.as_str().to_owned(),
                self.project_id.as_str().to_owned(),
                self.mission_id.as_str().to_owned(),
                self.work_product_id.as_str().to_owned(),
                self.project_revision.get().to_string(),
                self.mission_revision.get().to_string(),
                self.work_product_revision.get().to_string(),
                self.secret_reference_digest.as_str().to_owned(),
                self.credential_revision.get().to_string(),
                self.api_version.clone(),
            ],
        )
    }

    pub fn fence(&self) -> PermissionFence {
        PermissionFence {
            scope_digest: self.scope_digest.clone(),
            permission_digest: self.permission_digest.clone(),
            consent_digest: self.consent_digest.clone(),
            project_revision: self.project_revision,
            mission_revision: self.mission_revision,
            work_product_revision: self.work_product_revision,
        }
    }

    pub fn is_allowlisted(&self) -> bool {
        self.api_version == "v1"
            && self.filters.validate().is_ok()
            && self.filter_digest == self.filters.digest()
            && self.request_digest == self.digest()
    }
}

pub type ListRequest = GcpRecommenderListRequest;
pub type GetRequest = GcpRecommenderGetRequest;

#[derive(Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpRecommenderListResponse {
    pub records: Vec<GcpRecommenderRecord>,
    #[serde(skip)]
    pub next_page_token: Option<OpaquePageToken>,
    pub next_page_token_digest: Option<Digest>,
    pub page_complete: bool,
    pub page_number: u8,
    pub requested_page_token_digest: Option<Digest>,
    pub observed_scope_digest: Digest,
    pub observed_query_digest: Digest,
    pub observed_filter_digest: Digest,
    pub observed_permission_digest: Digest,
    pub observed_consent_digest: Digest,
    pub observed_project_revision: Revision,
    pub observed_mission_revision: Revision,
    pub observed_work_product_revision: Revision,
    pub observed_credential_revision: Revision,
    pub response_digest: Digest,
}

impl fmt::Debug for GcpRecommenderListResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GcpRecommenderListResponse")
            .field("records", &self.records)
            .field("next_page_token_digest", &self.next_page_token_digest)
            .field("page_complete", &self.page_complete)
            .field("page_number", &self.page_number)
            .field(
                "requested_page_token_digest",
                &self.requested_page_token_digest,
            )
            .field("observed_scope_digest", &self.observed_scope_digest)
            .field("observed_query_digest", &self.observed_query_digest)
            .field("observed_filter_digest", &self.observed_filter_digest)
            .field(
                "observed_permission_digest",
                &self.observed_permission_digest,
            )
            .field("observed_consent_digest", &self.observed_consent_digest)
            .field("observed_project_revision", &self.observed_project_revision)
            .field("observed_mission_revision", &self.observed_mission_revision)
            .field(
                "observed_work_product_revision",
                &self.observed_work_product_revision,
            )
            .field(
                "observed_credential_revision",
                &self.observed_credential_revision,
            )
            .field("response_digest", &self.response_digest)
            .finish_non_exhaustive()
    }
}

impl GcpRecommenderListResponse {
    pub fn new(
        request: &GcpRecommenderListRequest,
        records: Vec<GcpRecommenderRecord>,
        next_page_token: Option<OpaquePageToken>,
        page_complete: bool,
    ) -> Self {
        let next_page_token_digest = next_page_token.as_ref().map(OpaquePageToken::digest);
        let response_digest = compute_list_response_digest(
            &records,
            next_page_token_digest.as_ref(),
            page_complete,
            request.page_number,
            request.page_token_digest.as_ref(),
            &ProviderResponseFence {
                scope_digest: request.scope_digest.clone(),
                query_digest: request.query_digest.clone(),
                filter_digest: request.filter_digest.clone(),
                permission_digest: request.permission_digest.clone(),
                consent_digest: request.consent_digest.clone(),
                project_revision: request.project_revision,
                mission_revision: request.mission_revision,
                work_product_revision: request.work_product_revision,
                credential_revision: request.credential_revision,
            },
        );
        Self {
            records,
            next_page_token,
            next_page_token_digest,
            page_complete,
            page_number: request.page_number,
            requested_page_token_digest: request.page_token_digest.clone(),
            observed_scope_digest: request.scope_digest.clone(),
            observed_query_digest: request.query_digest.clone(),
            observed_filter_digest: request.filter_digest.clone(),
            observed_permission_digest: request.permission_digest.clone(),
            observed_consent_digest: request.consent_digest.clone(),
            observed_project_revision: request.project_revision,
            observed_mission_revision: request.mission_revision,
            observed_work_product_revision: request.work_product_revision,
            observed_credential_revision: request.credential_revision,
            response_digest,
        }
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        for record in &self.records {
            record.validate_digest()?;
        }
        let expected = compute_list_response_digest(
            &self.records,
            self.next_page_token_digest.as_ref(),
            self.page_complete,
            self.page_number,
            self.requested_page_token_digest.as_ref(),
            &ProviderResponseFence {
                scope_digest: self.observed_scope_digest.clone(),
                query_digest: self.observed_query_digest.clone(),
                filter_digest: self.observed_filter_digest.clone(),
                permission_digest: self.observed_permission_digest.clone(),
                consent_digest: self.observed_consent_digest.clone(),
                project_revision: self.observed_project_revision,
                mission_revision: self.observed_mission_revision,
                work_product_revision: self.observed_work_product_revision,
                credential_revision: self.observed_credential_revision,
            },
        );
        (expected == self.response_digest)
            .then_some(())
            .ok_or(ModelError::DigestMismatch)
    }
}

fn compute_list_response_digest(
    records: &[GcpRecommenderRecord],
    next_page_token_digest: Option<&Digest>,
    page_complete: bool,
    page_number: u8,
    requested_page_token_digest: Option<&Digest>,
    fence: &ProviderResponseFence,
) -> Digest {
    Digest::from_fields(
        "gcp-recommender-list-response/v1",
        &[
            records
                .iter()
                .enumerate()
                .map(|(index, record)| format!("{index}:{}", record.record_digest.as_str()))
                .collect::<Vec<_>>()
                .join(","),
            next_page_token_digest
                .map_or_else(|| "none".to_owned(), |digest| digest.as_str().to_owned()),
            page_complete.to_string(),
            page_number.to_string(),
            requested_page_token_digest
                .map_or_else(|| "none".to_owned(), |digest| digest.as_str().to_owned()),
            fence.scope_digest.as_str().to_owned(),
            fence.query_digest.as_str().to_owned(),
            fence.filter_digest.as_str().to_owned(),
            fence.permission_digest.as_str().to_owned(),
            fence.consent_digest.as_str().to_owned(),
            fence.project_revision.get().to_string(),
            fence.mission_revision.get().to_string(),
            fence.work_product_revision.get().to_string(),
            fence.credential_revision.get().to_string(),
        ],
    )
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpRecommenderGetResponse {
    pub record: GcpRecommenderRecord,
    pub observed_scope_digest: Digest,
    pub observed_query_digest: Digest,
    pub observed_filter_digest: Digest,
    pub observed_permission_digest: Digest,
    pub observed_consent_digest: Digest,
    pub observed_project_revision: Revision,
    pub observed_mission_revision: Revision,
    pub observed_work_product_revision: Revision,
    pub observed_credential_revision: Revision,
    pub response_digest: Digest,
}

impl GcpRecommenderGetResponse {
    pub fn new(request: &GcpRecommenderGetRequest, record: GcpRecommenderRecord) -> Self {
        let response_digest = compute_get_response_digest(
            &record,
            &ProviderResponseFence {
                scope_digest: request.scope_digest.clone(),
                query_digest: request.query_digest.clone(),
                filter_digest: request.filter_digest.clone(),
                permission_digest: request.permission_digest.clone(),
                consent_digest: request.consent_digest.clone(),
                project_revision: request.project_revision,
                mission_revision: request.mission_revision,
                work_product_revision: request.work_product_revision,
                credential_revision: request.credential_revision,
            },
        );
        Self {
            record,
            observed_scope_digest: request.scope_digest.clone(),
            observed_query_digest: request.query_digest.clone(),
            observed_filter_digest: request.filter_digest.clone(),
            observed_permission_digest: request.permission_digest.clone(),
            observed_consent_digest: request.consent_digest.clone(),
            observed_project_revision: request.project_revision,
            observed_mission_revision: request.mission_revision,
            observed_work_product_revision: request.work_product_revision,
            observed_credential_revision: request.credential_revision,
            response_digest,
        }
    }

    pub fn validate_digest(&self) -> Result<(), ModelError> {
        self.record.validate_digest()?;
        let expected = compute_get_response_digest(
            &self.record,
            &ProviderResponseFence {
                scope_digest: self.observed_scope_digest.clone(),
                query_digest: self.observed_query_digest.clone(),
                filter_digest: self.observed_filter_digest.clone(),
                permission_digest: self.observed_permission_digest.clone(),
                consent_digest: self.observed_consent_digest.clone(),
                project_revision: self.observed_project_revision,
                mission_revision: self.observed_mission_revision,
                work_product_revision: self.observed_work_product_revision,
                credential_revision: self.observed_credential_revision,
            },
        );
        (expected == self.response_digest)
            .then_some(())
            .ok_or(ModelError::DigestMismatch)
    }
}

fn compute_get_response_digest(
    record: &GcpRecommenderRecord,
    fence: &ProviderResponseFence,
) -> Digest {
    Digest::from_fields(
        "gcp-recommender-get-response/v1",
        &[
            record.record_digest.as_str().to_owned(),
            fence.scope_digest.as_str().to_owned(),
            fence.query_digest.as_str().to_owned(),
            fence.filter_digest.as_str().to_owned(),
            fence.permission_digest.as_str().to_owned(),
            fence.consent_digest.as_str().to_owned(),
            fence.project_revision.get().to_string(),
            fence.mission_revision.get().to_string(),
            fence.work_product_revision.get().to_string(),
            fence.credential_revision.get().to_string(),
        ],
    )
}

pub type GcpRecommenderListPage = GcpRecommenderListResponse;
pub type GcpRecommendationListResponse = GcpRecommenderListResponse;
pub type GcpRecommendationGetResponse = GcpRecommenderGetResponse;

pub trait GcpRecommenderTransport: fmt::Debug {
    fn provenance(&self) -> ProviderProvenance;

    fn list(
        &mut self,
        request: &GcpRecommenderListRequest,
    ) -> Result<GcpRecommenderListResponse, TransportError>;

    fn get(
        &mut self,
        request: &GcpRecommenderGetRequest,
    ) -> Result<GcpRecommenderGetResponse, TransportError>;
}

pub trait GcpRecommenderProviderApi: fmt::Debug {
    fn definition(&self) -> &GcpRecommenderProviderDefinition;

    fn provenance(&self) -> ProviderProvenance {
        self.definition().provenance
    }

    fn list(
        &mut self,
        request: &GcpRecommenderListRequest,
    ) -> Result<GcpRecommenderListResponse, TransportError>;

    fn get(
        &mut self,
        request: &GcpRecommenderGetRequest,
    ) -> Result<GcpRecommenderGetResponse, TransportError>;
}

#[derive(Debug)]
pub struct GcpRecommenderProvider<T: GcpRecommenderTransport> {
    transport: T,
    definition: GcpRecommenderProviderDefinition,
}

impl<T: GcpRecommenderTransport> GcpRecommenderProvider<T> {
    pub fn new(
        transport: T,
        provider_version: impl Into<String>,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        if transport.provenance() != provenance {
            return Err(ProviderDefinitionError::ProvenanceMismatch);
        }
        let definition = GcpRecommenderProviderDefinition::new(provider_version, provenance)?;
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn layer1(
        transport: T,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        Self::new(
            transport,
            GCP_RECOMMENDER_RESULT_PROVIDER_VERSION,
            provenance,
        )
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn definition(&self) -> &GcpRecommenderProviderDefinition {
        &self.definition
    }

    pub fn provenance(&self) -> ProviderProvenance {
        self.definition.provenance
    }

    pub fn list(
        &mut self,
        request: &GcpRecommenderListRequest,
    ) -> Result<GcpRecommenderListResponse, TransportError> {
        self.transport.list(request)
    }

    pub fn get(
        &mut self,
        request: &GcpRecommenderGetRequest,
    ) -> Result<GcpRecommenderGetResponse, TransportError> {
        self.transport.get(request)
    }
}

impl<T: GcpRecommenderTransport> GcpRecommenderProviderApi for GcpRecommenderProvider<T> {
    fn definition(&self) -> &GcpRecommenderProviderDefinition {
        &self.definition
    }

    fn list(
        &mut self,
        request: &GcpRecommenderListRequest,
    ) -> Result<GcpRecommenderListResponse, TransportError> {
        self.transport.list(request)
    }

    fn get(
        &mut self,
        request: &GcpRecommenderGetRequest,
    ) -> Result<GcpRecommenderGetResponse, TransportError> {
        self.transport.get(request)
    }
}

pub type GcpRecommenderProviderAdapter<T> = GcpRecommenderProvider<T>;

#[derive(Clone, Debug)]
pub struct FixtureGcpRecommenderTransport {
    list_responses: VecDeque<Result<GcpRecommenderListResponse, TransportError>>,
    get_responses: VecDeque<Result<GcpRecommenderGetResponse, TransportError>>,
}

impl FixtureGcpRecommenderTransport {
    pub fn new(
        list_response: GcpRecommenderListResponse,
        get_response: GcpRecommenderGetResponse,
    ) -> Self {
        Self::from_results(vec![Ok(list_response)], vec![Ok(get_response)])
    }

    pub fn from_results(
        list_responses: Vec<Result<GcpRecommenderListResponse, TransportError>>,
        get_responses: Vec<Result<GcpRecommenderGetResponse, TransportError>>,
    ) -> Self {
        Self {
            list_responses: list_responses.into_iter().collect(),
            get_responses: get_responses.into_iter().collect(),
        }
    }

    pub fn push_list_response(
        &mut self,
        response: Result<GcpRecommenderListResponse, TransportError>,
    ) {
        self.list_responses.push_back(response);
    }

    pub fn push_get_response(
        &mut self,
        response: Result<GcpRecommenderGetResponse, TransportError>,
    ) {
        self.get_responses.push_back(response);
    }
}

impl GcpRecommenderTransport for FixtureGcpRecommenderTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Fixture
    }

    fn list(
        &mut self,
        _request: &GcpRecommenderListRequest,
    ) -> Result<GcpRecommenderListResponse, TransportError> {
        self.list_responses.pop_front().unwrap_or_else(|| {
            Err(TransportError::new(
                ProviderErrorKind::Unknown,
                None,
                "fixture exhausted",
            ))
        })
    }

    fn get(
        &mut self,
        _request: &GcpRecommenderGetRequest,
    ) -> Result<GcpRecommenderGetResponse, TransportError> {
        self.get_responses.pop_front().unwrap_or_else(|| {
            Err(TransportError::new(
                ProviderErrorKind::Unknown,
                None,
                "fixture exhausted",
            ))
        })
    }
}

pub type FakeGcpRecommenderTransport = FixtureGcpRecommenderTransport;

#[derive(Clone, Debug)]
pub struct RecordingGcpRecommenderTransport {
    list_responses: VecDeque<Result<GcpRecommenderListResponse, TransportError>>,
    get_responses: VecDeque<Result<GcpRecommenderGetResponse, TransportError>>,
    list_requests: Vec<GcpRecommenderListRequest>,
    get_requests: Vec<GcpRecommenderGetRequest>,
}

impl RecordingGcpRecommenderTransport {
    pub fn new(
        list_response: GcpRecommenderListResponse,
        get_response: GcpRecommenderGetResponse,
    ) -> Self {
        Self {
            list_responses: VecDeque::from([Ok(list_response)]),
            get_responses: VecDeque::from([Ok(get_response)]),
            list_requests: Vec::new(),
            get_requests: Vec::new(),
        }
    }

    pub fn from_results(
        list_responses: Vec<Result<GcpRecommenderListResponse, TransportError>>,
        get_responses: Vec<Result<GcpRecommenderGetResponse, TransportError>>,
    ) -> Self {
        Self {
            list_responses: list_responses.into_iter().collect(),
            get_responses: get_responses.into_iter().collect(),
            list_requests: Vec::new(),
            get_requests: Vec::new(),
        }
    }

    pub fn list_requests(&self) -> &[GcpRecommenderListRequest] {
        &self.list_requests
    }

    pub fn get_requests(&self) -> &[GcpRecommenderGetRequest] {
        &self.get_requests
    }

    pub fn requests(&self) -> (&[GcpRecommenderListRequest], &[GcpRecommenderGetRequest]) {
        (&self.list_requests, &self.get_requests)
    }
}

impl GcpRecommenderTransport for RecordingGcpRecommenderTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Recording
    }

    fn list(
        &mut self,
        request: &GcpRecommenderListRequest,
    ) -> Result<GcpRecommenderListResponse, TransportError> {
        self.list_requests.push(request.clone());
        self.list_responses.pop_front().unwrap_or_else(|| {
            Err(TransportError::new(
                ProviderErrorKind::Unknown,
                None,
                "recording exhausted",
            ))
        })
    }

    fn get(
        &mut self,
        request: &GcpRecommenderGetRequest,
    ) -> Result<GcpRecommenderGetResponse, TransportError> {
        self.get_requests.push(request.clone());
        self.get_responses.pop_front().unwrap_or_else(|| {
            Err(TransportError::new(
                ProviderErrorKind::Unknown,
                None,
                "recording exhausted",
            ))
        })
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackGcpRecommenderTransport {
    response_list: VecDeque<Result<GcpRecommenderListResponse, TransportError>>,
    response_get: VecDeque<Result<GcpRecommenderGetResponse, TransportError>>,
    requests_list: Vec<GcpRecommenderListRequest>,
    requests_get: Vec<GcpRecommenderGetRequest>,
}

impl LoopbackGcpRecommenderTransport {
    pub fn new(
        list_response: GcpRecommenderListResponse,
        get_response: GcpRecommenderGetResponse,
    ) -> Self {
        Self {
            response_list: VecDeque::from([Ok(list_response)]),
            response_get: VecDeque::from([Ok(get_response)]),
            requests_list: Vec::new(),
            requests_get: Vec::new(),
        }
    }

    pub fn list_requests(&self) -> &[GcpRecommenderListRequest] {
        &self.requests_list
    }

    pub fn get_requests(&self) -> &[GcpRecommenderGetRequest] {
        &self.requests_get
    }
}

impl GcpRecommenderTransport for LoopbackGcpRecommenderTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Loopback
    }

    fn list(
        &mut self,
        request: &GcpRecommenderListRequest,
    ) -> Result<GcpRecommenderListResponse, TransportError> {
        self.requests_list.push(request.clone());
        self.response_list.pop_front().unwrap_or_else(|| {
            Err(TransportError::new(
                ProviderErrorKind::Unknown,
                None,
                "loopback exhausted",
            ))
        })
    }

    fn get(
        &mut self,
        request: &GcpRecommenderGetRequest,
    ) -> Result<GcpRecommenderGetResponse, TransportError> {
        self.requests_get.push(request.clone());
        self.response_get.pop_front().unwrap_or_else(|| {
            Err(TransportError::new(
                ProviderErrorKind::Unknown,
                None,
                "loopback exhausted",
            ))
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvGcpRecommenderTransport;

impl BlockedEnvGcpRecommenderTransport {
    pub const fn new() -> Self {
        Self
    }
}

impl GcpRecommenderTransport for BlockedEnvGcpRecommenderTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }

    fn list(
        &mut self,
        _request: &GcpRecommenderListRequest,
    ) -> Result<GcpRecommenderListResponse, TransportError> {
        Err(TransportError::blocked_env())
    }

    fn get(
        &mut self,
        _request: &GcpRecommenderGetRequest,
    ) -> Result<GcpRecommenderGetResponse, TransportError> {
        Err(TransportError::blocked_env())
    }
}

pub type FixtureTransport = FixtureGcpRecommenderTransport;
pub type RecordingTransport = RecordingGcpRecommenderTransport;
pub type LoopbackTransport = LoopbackGcpRecommenderTransport;
pub type BlockedEnvTransport = BlockedEnvGcpRecommenderTransport;
