use std::{collections::BTreeMap, fmt};

use serde::Serialize;
use thiserror::Error;

use crate::{
    GCP_RECOMMENDER_RESULT_CONTRACT_VERSION, GCP_RECOMMENDER_RESULT_PLUGIN_VERSION,
    GCP_RECOMMENDER_RESULT_PROVIDER_ID, GCP_RECOMMENDER_RESULT_SCHEMA_VERSION,
    GCP_RECOMMENDER_RESULT_SERVICE_ID,
    model::{
        Digest, GcpRecommenderQuery, GcpRecommenderRecord, GcpRecommenderRegistration,
        GcpRecommenderScope, GcpResultKind, Layer1Authority, ModelError, PartialReason,
        ProviderErrorEvidence, ProviderErrorKind, ReadOperation, RegistrationRevocationReceipt,
        RegistrationState, ResultProjection, ResultVersionFence, Revision, SecretReference,
    },
    provider::{
        GcpRecommenderGetRequest, GcpRecommenderGetResponse, GcpRecommenderListRequest,
        GcpRecommenderListResponse, GcpRecommenderProviderApi, ProviderProvenance, TransportError,
    },
};

pub const EVIDENCE_POLICY_VERSION: &str = "gcp-recommender-redacted-evidence/v1";

pub fn evidence_policy_digest() -> Digest {
    Digest::from_fields(
        EVIDENCE_POLICY_VERSION,
        &[
            "ids=true".to_owned(),
            "priority=true".to_owned(),
            "category=true".to_owned(),
            "state=true".to_owned(),
            "timestamps=true".to_owned(),
            "impact=true".to_owned(),
            "target_resources=digest_only".to_owned(),
            "content=digest_only".to_owned(),
            "raw_descriptions=false".to_owned(),
            "custom_structs=false".to_owned(),
            "principals=false".to_owned(),
            "operation_plans=false".to_owned(),
            "projected_savings=false".to_owned(),
        ],
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    max_attempts: u8,
    base_delay_seconds: u64,
    max_delay_seconds: u64,
}

impl RetryPolicy {
    pub fn new(
        max_attempts: u8,
        base_delay_seconds: u64,
        max_delay_seconds: u64,
    ) -> Result<Self, GcpRecommenderServiceError> {
        if max_attempts == 0 || max_attempts > 5 || base_delay_seconds > max_delay_seconds {
            return Err(GcpRecommenderServiceError::InvalidRetryPolicy);
        }
        Ok(Self {
            max_attempts,
            base_delay_seconds,
            max_delay_seconds,
        })
    }

    pub const fn max_attempts(self) -> u8 {
        self.max_attempts
    }

    fn delay_seconds(self, attempt: u8, retry_after_seconds: Option<u64>) -> u64 {
        retry_after_seconds.unwrap_or_else(|| {
            self.base_delay_seconds
                .saturating_mul(2_u64.saturating_pow(u32::from(attempt.saturating_sub(1))))
                .min(self.max_delay_seconds)
        })
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_delay_seconds: 1,
            max_delay_seconds: 30,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetryEvidence {
    pub operation: String,
    pub failed_attempt: u8,
    pub delay_seconds: u64,
    pub kind: ProviderErrorKind,
    pub status_code: Option<u16>,
    pub diagnostic_digest: Digest,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum GcpRecommenderServiceError {
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error("GCP Recommender service definition drifted")]
    DefinitionDrift,
    #[error("GCP Recommender registration is revoked or drifted")]
    RegistrationRevoked,
    #[error("GCP Recommender SecretReference is revoked or out of scope")]
    SecretRevoked,
    #[error("GCP Recommender scope is not authorized for this operation")]
    ScopeMismatch,
    #[error("GCP Recommender read permission is missing")]
    MissingReadPermission,
    #[error("GCP Recommender consent is stale or not read-only")]
    ConsentMismatch,
    #[error("GCP Recommender query or filter drifted")]
    QueryMismatch,
    #[error("GCP Recommender response evidence was tampered")]
    TamperedEvidence,
    #[error("GCP Recommender response scope or permission fence drifted")]
    FenceMismatch,
    #[error("GCP Recommender list page token replay or page loop was rejected")]
    PageLoop,
    #[error("GCP Recommender response page was truncated")]
    TruncatedPage,
    #[error("GCP Recommender result etag drifted")]
    EtagDrift,
    #[error("GCP Recommender result revision drifted")]
    RevisionDrift,
    #[error("GCP Recommender response does not match the requested result")]
    ResultMismatch,
    #[error("GCP Recommender response does not match the requested filter")]
    FilterMismatch,
    #[error("GCP Recommender result target is outside the scope")]
    TargetOutOfScope,
    #[error("GCP Recommender response returned too many records")]
    BoundExceeded,
    #[error("GCP Recommender retry policy is invalid")]
    InvalidRetryPolicy,
    #[error("provider returned {kind:?} ({status_code:?})")]
    Provider {
        kind: ProviderErrorKind,
        status_code: Option<u16>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcpRecommenderServiceDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub plugin_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub contract_digest: Digest,
    pub read_only: bool,
    pub live_execution: bool,
    pub external_writes: bool,
    pub marks_recommendation: bool,
    pub executes_operation_group: bool,
    pub adopts_outcome: bool,
}

impl GcpRecommenderServiceDefinition {
    pub fn new() -> Self {
        Self {
            schema_version: GCP_RECOMMENDER_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: GCP_RECOMMENDER_RESULT_CONTRACT_VERSION.to_owned(),
            plugin_version: GCP_RECOMMENDER_RESULT_PLUGIN_VERSION.to_owned(),
            service_id: GCP_RECOMMENDER_RESULT_SERVICE_ID.to_owned(),
            provider_id: GCP_RECOMMENDER_RESULT_PROVIDER_ID.to_owned(),
            consumer_id: crate::GCP_RECOMMENDER_RESULT_CONSUMER_ID.to_owned(),
            contract_digest: crate::contract_digest(),
            read_only: true,
            live_execution: false,
            external_writes: false,
            marks_recommendation: false,
            executes_operation_group: false,
            adopts_outcome: false,
        }
    }

    pub fn validate(&self) -> Result<(), GcpRecommenderServiceError> {
        if self.schema_version != GCP_RECOMMENDER_RESULT_SCHEMA_VERSION
            || self.contract_version != GCP_RECOMMENDER_RESULT_CONTRACT_VERSION
            || self.plugin_version != GCP_RECOMMENDER_RESULT_PLUGIN_VERSION
            || self.service_id != GCP_RECOMMENDER_RESULT_SERVICE_ID
            || self.provider_id != GCP_RECOMMENDER_RESULT_PROVIDER_ID
            || self.consumer_id != crate::GCP_RECOMMENDER_RESULT_CONSUMER_ID
            || self.contract_digest != crate::contract_digest()
            || !self.read_only
            || self.live_execution
            || self.external_writes
            || self.marks_recommendation
            || self.executes_operation_group
            || self.adopts_outcome
        {
            Err(GcpRecommenderServiceError::DefinitionDrift)
        } else {
            Ok(())
        }
    }
}

impl Default for GcpRecommenderServiceDefinition {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadTarget {
    List,
    Get(crate::ResultId),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpRecommenderEvidence {
    pub operation: ReadOperation,
    pub result_kind: GcpResultKind,
    pub result_id: Option<crate::ResultId>,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub query_digest: Digest,
    pub filter_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub project_revision: Revision,
    pub mission_revision: Revision,
    pub work_product_revision: Revision,
    pub records: Vec<GcpRecommenderRecord>,
    pub page_count: u8,
    pub page_token_digests: Vec<Digest>,
    pub response_digests: Vec<Digest>,
    pub retries: Vec<RetryEvidence>,
    pub provider_errors: Vec<ProviderErrorEvidence>,
    pub projection: ResultProjection,
    pub partial_reason: Option<PartialReason>,
    pub provider_provenance: ProviderProvenance,
    pub redacted: bool,
    pub raw_descriptions: bool,
    pub custom_struct_payloads: bool,
    pub principals: bool,
    pub operation_plans: bool,
    pub projected_savings: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub authority: Layer1Authority,
    pub response_digest: Digest,
    pub evidence_digest: Digest,
}

impl GcpRecommenderEvidence {
    #[allow(clippy::too_many_arguments)]
    fn new(
        scope: &GcpRecommenderScope,
        query: &GcpRecommenderQuery,
        registration: &GcpRecommenderRegistration,
        provider_digest: Digest,
        operation: ReadOperation,
        result_id: Option<crate::ResultId>,
        records: Vec<GcpRecommenderRecord>,
        page_count: u8,
        page_token_digests: Vec<Digest>,
        response_digests: Vec<Digest>,
        retries: Vec<RetryEvidence>,
        provider_errors: Vec<ProviderErrorEvidence>,
        projection: ResultProjection,
        partial_reason: Option<PartialReason>,
        provider_provenance: ProviderProvenance,
    ) -> Self {
        let response_digest = Digest::from_fields(
            "gcp-recommender-response-set/v1",
            &response_digests
                .iter()
                .map(|digest| digest.as_str().to_owned())
                .collect::<Vec<_>>(),
        );
        let evidence_digest = compute_evidence_digest(
            operation,
            &scope.digest(),
            &scope.permission().digest(),
            &scope.consent().digest(),
            &query.digest(),
            &query.filters().digest(),
            &registration.registration_digest,
            &provider_digest,
            result_id.as_ref(),
            &records,
            page_count,
            &page_token_digests,
            &response_digest,
            &retries,
            &provider_errors,
            projection,
            partial_reason,
            provider_provenance,
        );
        Self {
            operation,
            result_kind: scope.result_kind().clone(),
            result_id,
            scope_digest: scope.digest(),
            permission_digest: scope.permission().digest(),
            consent_digest: scope.consent().digest(),
            query_digest: query.digest(),
            filter_digest: query.filters().digest(),
            registration_digest: registration.registration_digest.clone(),
            provider_digest,
            project_revision: scope.project().revision(),
            mission_revision: scope.mission().revision(),
            work_product_revision: scope.work_product().revision(),
            records,
            page_count,
            page_token_digests,
            response_digests,
            retries,
            provider_errors,
            projection,
            partial_reason,
            provider_provenance,
            redacted: true,
            raw_descriptions: false,
            custom_struct_payloads: false,
            principals: false,
            operation_plans: false,
            projected_savings: false,
            connected: false,
            native: false,
            first_party: false,
            authority: Layer1Authority,
            response_digest,
            evidence_digest,
        }
    }

    pub fn validate_digest(&self) -> Result<(), GcpRecommenderServiceError> {
        if self
            .records
            .iter()
            .any(|record| record.validate_digest().is_err())
            || !self.redacted
            || self.raw_descriptions
            || self.custom_struct_payloads
            || self.principals
            || self.operation_plans
            || self.projected_savings
            || self.connected
            || self.native
            || self.first_party
        {
            return Err(GcpRecommenderServiceError::TamperedEvidence);
        }
        let response_digest = Digest::from_fields(
            "gcp-recommender-response-set/v1",
            &self
                .response_digests
                .iter()
                .map(|digest| digest.as_str().to_owned())
                .collect::<Vec<_>>(),
        );
        let expected = compute_evidence_digest(
            self.operation,
            &self.scope_digest,
            &self.permission_digest,
            &self.consent_digest,
            &self.query_digest,
            &self.filter_digest,
            &self.registration_digest,
            &self.provider_digest,
            self.result_id.as_ref(),
            &self.records,
            self.page_count,
            &self.page_token_digests,
            &response_digest,
            &self.retries,
            &self.provider_errors,
            self.projection,
            self.partial_reason,
            self.provider_provenance,
        );
        if response_digest != self.response_digest || expected != self.evidence_digest {
            Err(GcpRecommenderServiceError::TamperedEvidence)
        } else {
            Ok(())
        }
    }

    pub fn is_decision_ready(&self) -> bool {
        self.projection.is_decision_ready()
    }

    pub fn digest(&self) -> &Digest {
        &self.evidence_digest
    }
}

fn compute_evidence_digest(
    operation: ReadOperation,
    scope_digest: &Digest,
    permission_digest: &Digest,
    consent_digest: &Digest,
    query_digest: &Digest,
    filter_digest: &Digest,
    registration_digest: &Digest,
    provider_digest: &Digest,
    result_id: Option<&crate::ResultId>,
    records: &[GcpRecommenderRecord],
    page_count: u8,
    page_token_digests: &[Digest],
    response_digest: &Digest,
    retries: &[RetryEvidence],
    provider_errors: &[ProviderErrorEvidence],
    projection: ResultProjection,
    partial_reason: Option<PartialReason>,
    provider_provenance: ProviderProvenance,
) -> Digest {
    Digest::from_fields(
        "gcp-recommender-evidence/v1",
        &[
            format!("{operation:?}"),
            scope_digest.as_str().to_owned(),
            permission_digest.as_str().to_owned(),
            consent_digest.as_str().to_owned(),
            query_digest.as_str().to_owned(),
            filter_digest.as_str().to_owned(),
            registration_digest.as_str().to_owned(),
            provider_digest.as_str().to_owned(),
            result_id.map_or_else(|| "none".to_owned(), |id| id.as_str().to_owned()),
            records
                .iter()
                .map(|record| record.record_digest.as_str().to_owned())
                .collect::<Vec<_>>()
                .join(","),
            page_count.to_string(),
            page_token_digests
                .iter()
                .map(|digest| digest.as_str().to_owned())
                .collect::<Vec<_>>()
                .join(","),
            response_digest.as_str().to_owned(),
            retries
                .iter()
                .map(|retry| {
                    format!(
                        "{}:{}:{}:{:?}:{}:{}",
                        retry.operation,
                        retry.failed_attempt,
                        retry.delay_seconds,
                        retry.kind,
                        retry.status_code.map_or(0, u16::from),
                        retry.diagnostic_digest.as_str()
                    )
                })
                .collect::<Vec<_>>()
                .join(","),
            provider_errors
                .iter()
                .map(|error| error.error_digest.as_str().to_owned())
                .collect::<Vec<_>>()
                .join(","),
            format!("{projection:?}"),
            partial_reason.map_or_else(|| "none".to_owned(), |reason| format!("{reason:?}")),
            format!("{provider_provenance:?}"),
        ],
    )
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpRecommenderProposal {
    pub operation: ReadOperation,
    pub result_id: Option<crate::ResultId>,
    pub evidence: GcpRecommenderEvidence,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub plugin_version: String,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub scope_digest: Digest,
    pub query_digest: Digest,
    pub filter_digest: Digest,
    pub provider_digest: Digest,
    pub proposal_only: bool,
    pub read_only: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub marks_recommendation: bool,
    pub executes_operation_group: bool,
    pub adopts_outcome: bool,
    pub proposal_digest: Digest,
}

pub type RecommendationResultProposal = GcpRecommenderProposal;
pub type GcpRecommenderResultProposal = GcpRecommenderProposal;

impl GcpRecommenderProposal {
    fn new(
        registration: &GcpRecommenderRegistration,
        scope: &GcpRecommenderScope,
        query: &GcpRecommenderQuery,
        provider_digest: Digest,
        evidence: GcpRecommenderEvidence,
    ) -> Self {
        let mut proposal = Self {
            operation: evidence.operation,
            result_id: evidence.result_id.clone(),
            evidence,
            contract_version: GCP_RECOMMENDER_RESULT_CONTRACT_VERSION.to_owned(),
            contract_digest: crate::contract_digest(),
            plugin_version: GCP_RECOMMENDER_RESULT_PLUGIN_VERSION.to_owned(),
            registration_digest: registration.registration_digest.clone(),
            registration_revision: registration.registration_revision,
            scope_digest: scope.digest(),
            query_digest: query.digest(),
            filter_digest: query.filters().digest(),
            provider_digest,
            proposal_only: true,
            read_only: true,
            native: false,
            connected: false,
            first_party: false,
            marks_recommendation: false,
            executes_operation_group: false,
            adopts_outcome: false,
            proposal_digest: Digest::from_text("proposal-placeholder"),
        };
        proposal.proposal_digest = proposal.compute_digest();
        proposal
    }

    fn compute_digest(&self) -> Digest {
        let evidence_payload =
            serde_json::to_string(&self.evidence).expect("typed evidence serializes");
        Digest::from_fields(
            "gcp-recommender-proposal/v1",
            &[
                format!("{:?}", self.operation),
                self.result_id
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), |id| id.as_str().to_owned()),
                evidence_payload,
                self.contract_version.clone(),
                self.contract_digest.as_str().to_owned(),
                self.plugin_version.clone(),
                self.registration_digest.as_str().to_owned(),
                self.registration_revision.get().to_string(),
                self.scope_digest.as_str().to_owned(),
                self.query_digest.as_str().to_owned(),
                self.filter_digest.as_str().to_owned(),
                self.provider_digest.as_str().to_owned(),
                self.proposal_only.to_string(),
                self.read_only.to_string(),
                self.native.to_string(),
                self.connected.to_string(),
                self.first_party.to_string(),
                self.marks_recommendation.to_string(),
                self.executes_operation_group.to_string(),
                self.adopts_outcome.to_string(),
            ],
        )
    }

    pub fn validate_digest(&self) -> Result<(), GcpRecommenderServiceError> {
        if self.proposal_digest == self.compute_digest() {
            Ok(())
        } else {
            Err(GcpRecommenderServiceError::TamperedEvidence)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpRecommenderObservationReceipt {
    pub receipt_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub projection: ResultProjection,
    pub provenance: ProviderProvenance,
    pub recorded: bool,
    pub durable: bool,
    pub connected: bool,
    pub native: bool,
    pub independent_native_readback: bool,
    pub adopts_outcome: bool,
}

pub type GcpRecommenderResultReceipt = GcpRecommenderObservationReceipt;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpRecommenderReadbackReceipt {
    pub receipt_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub verified_against_proposal: bool,
    pub independent_native_readback: bool,
    pub connected: bool,
    pub native: bool,
}

pub struct GcpRecommenderService<P: GcpRecommenderProviderApi> {
    service_definition: GcpRecommenderServiceDefinition,
    provider: P,
    scope: GcpRecommenderScope,
    query: GcpRecommenderQuery,
    secret: SecretReference,
    registration: GcpRecommenderRegistration,
    retry_policy: RetryPolicy,
}

pub type GcpRecommenderResultService<P> = GcpRecommenderService<P>;

impl<P: GcpRecommenderProviderApi> fmt::Debug for GcpRecommenderService<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GcpRecommenderService")
            .field("service_definition", &self.service_definition)
            .field("provider", &self.provider)
            .field("scope_digest", &self.scope.digest())
            .field("query_digest", &self.query.digest())
            .field("secret", &self.secret)
            .field("registration", &self.registration)
            .field("retry_policy", &self.retry_policy)
            .finish()
    }
}

impl<P: GcpRecommenderProviderApi> GcpRecommenderService<P> {
    pub fn new(
        scope: GcpRecommenderScope,
        secret: SecretReference,
        provider: P,
    ) -> Result<Self, GcpRecommenderServiceError> {
        Self::with_query(
            scope,
            GcpRecommenderQuery::default(),
            secret,
            provider,
            RetryPolicy::default(),
        )
    }

    pub fn with_query(
        scope: GcpRecommenderScope,
        query: GcpRecommenderQuery,
        secret: SecretReference,
        provider: P,
        retry_policy: RetryPolicy,
    ) -> Result<Self, GcpRecommenderServiceError> {
        scope.validate()?;
        query
            .validate_against(&scope)
            .map_err(|error| match error {
                ModelError::MissingReadPermission => {
                    GcpRecommenderServiceError::MissingReadPermission
                }
                ModelError::InvalidFilter => GcpRecommenderServiceError::QueryMismatch,
                other => GcpRecommenderServiceError::Model(other),
            })?;
        secret.validate_scope(&scope)?;
        let service_definition = GcpRecommenderServiceDefinition::new();
        service_definition.validate()?;
        provider
            .definition()
            .validate()
            .map_err(|_| GcpRecommenderServiceError::DefinitionDrift)?;
        let registration = GcpRecommenderRegistration::bind(
            &scope,
            &query,
            provider.definition().provider_id.as_str(),
            &provider.definition().provider_version,
            &provider.definition().api_version,
            provider.definition().provider_digest(),
            secret.digest(),
            evidence_policy_digest(),
        )?;
        Ok(Self {
            service_definition,
            provider,
            scope,
            query,
            secret,
            registration,
            retry_policy,
        })
    }

    pub fn new_with_query(
        scope: GcpRecommenderScope,
        secret: SecretReference,
        provider: P,
        query: GcpRecommenderQuery,
        retry_policy: RetryPolicy,
    ) -> Result<Self, GcpRecommenderServiceError> {
        Self::with_query(scope, query, secret, provider, retry_policy)
    }

    pub fn service_definition(&self) -> &GcpRecommenderServiceDefinition {
        &self.service_definition
    }

    pub fn provider_definition(&self) -> &crate::GcpRecommenderProviderDefinition {
        self.provider.definition()
    }

    pub fn provider(&self) -> &P {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut P {
        &mut self.provider
    }

    pub fn scope(&self) -> &GcpRecommenderScope {
        &self.scope
    }

    pub fn query(&self) -> &GcpRecommenderQuery {
        &self.query
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret
    }

    pub fn registration(&self) -> &GcpRecommenderRegistration {
        &self.registration
    }

    pub fn retry_policy(&self) -> RetryPolicy {
        self.retry_policy
    }

    pub fn is_active(&self) -> bool {
        self.registration.state == RegistrationState::Active && !self.secret.is_revoked()
    }

    pub fn revoke_registration(
        &mut self,
    ) -> Result<RegistrationRevocationReceipt, GcpRecommenderServiceError> {
        self.registration
            .revoke()
            .map_err(GcpRecommenderServiceError::Model)
    }

    pub fn restore_registration(&mut self) -> Result<(), GcpRecommenderServiceError> {
        self.registration
            .restore()
            .map_err(GcpRecommenderServiceError::Model)
    }

    pub fn revoke_secret(&mut self) -> Result<(), GcpRecommenderServiceError> {
        self.secret
            .revoke()
            .map_err(GcpRecommenderServiceError::Model)
    }

    pub fn restore_secret(&mut self) -> Result<(), GcpRecommenderServiceError> {
        self.secret
            .restore()
            .map_err(GcpRecommenderServiceError::Model)
    }

    pub fn read(&mut self) -> Result<GcpRecommenderEvidence, GcpRecommenderServiceError> {
        self.read_list()
    }

    pub fn list(&mut self) -> Result<GcpRecommenderEvidence, GcpRecommenderServiceError> {
        self.read_list()
    }

    pub fn read_list(&mut self) -> Result<GcpRecommenderEvidence, GcpRecommenderServiceError> {
        self.ensure_ready(ReadOperation::List)?;
        let mut token: Option<crate::OpaquePageToken> = None;
        let mut page_number = 1_u8;
        let mut records = Vec::new();
        let mut page_token_digests = Vec::new();
        let mut response_digests = Vec::new();
        let mut retries = Vec::new();
        let mut provider_errors = Vec::new();
        let mut seen_tokens = std::collections::BTreeSet::new();
        let mut versions = BTreeMap::new();
        let mut projection = ResultProjection::Complete;
        let mut partial_reason = None;

        loop {
            let request = self.list_request(page_number, token.clone());
            if let Some(token_digest) = request.page_token_digest() {
                page_token_digests.push(token_digest.clone());
            }
            let response = match self.call_list(&request, &mut retries, &mut provider_errors) {
                Ok(response) => response,
                Err(error) => {
                    if records.is_empty() {
                        projection = projection_for_error(error.kind);
                    } else {
                        projection = ResultProjection::Partial;
                        partial_reason = Some(PartialReason::ProviderError);
                    }
                    break;
                }
            };
            self.validate_list_response(&request, &response)?;
            response_digests.push(response.response_digest.clone());
            if let Some(next_digest) = &response.next_page_token_digest {
                page_token_digests.push(next_digest.clone());
            }
            if response.records.len() > request.page_size as usize {
                projection = ResultProjection::Partial;
                partial_reason = Some(PartialReason::TruncatedPage);
                break;
            }
            for record in &response.records {
                if let Some(previous) =
                    versions.insert(record.result_id.clone(), record.version_fence())
                {
                    if previous.etag_digest != record.etag_digest {
                        projection = ResultProjection::Partial;
                        partial_reason = Some(PartialReason::EtagDrift);
                        break;
                    }
                    if previous.revision != record.revision {
                        projection = ResultProjection::Partial;
                        partial_reason = Some(PartialReason::RevisionDrift);
                        break;
                    }
                }
                records.push(record.clone());
                if records.len() >= self.query.max_results() as usize {
                    projection = ResultProjection::Partial;
                    partial_reason = Some(PartialReason::ResultCap);
                    break;
                }
            }
            if partial_reason.is_some() {
                break;
            }
            if response.next_page_token.is_none() {
                if response.page_complete {
                    projection = if records.is_empty() {
                        ResultProjection::Empty
                    } else {
                        ResultProjection::Complete
                    };
                } else {
                    projection = ResultProjection::Partial;
                    partial_reason = Some(PartialReason::MissingPageToken);
                }
                break;
            }
            if page_number >= self.query.max_pages() {
                projection = ResultProjection::Partial;
                partial_reason = Some(PartialReason::PageCap);
                break;
            }
            let next = response
                .next_page_token
                .clone()
                .ok_or(GcpRecommenderServiceError::PageLoop)?;
            if !seen_tokens.insert(next.digest()) {
                return Err(GcpRecommenderServiceError::PageLoop);
            }
            token = Some(next);
            page_number = page_number.saturating_add(1);
        }

        Ok(self.finish_evidence(
            ReadOperation::List,
            None,
            records,
            page_number,
            page_token_digests,
            response_digests,
            retries,
            provider_errors,
            projection,
            partial_reason,
        ))
    }

    pub fn read_get(
        &mut self,
        result_id: crate::ResultId,
        expected: Option<ResultVersionFence>,
    ) -> Result<GcpRecommenderEvidence, GcpRecommenderServiceError> {
        self.ensure_ready(ReadOperation::Get)?;
        let request = self.get_request(result_id.clone(), expected.clone());
        let mut retries = Vec::new();
        let mut provider_errors = Vec::new();
        let response = match self.call_get(&request, &mut retries, &mut provider_errors) {
            Ok(response) => response,
            Err(error) => {
                return Ok(self.finish_evidence(
                    ReadOperation::Get,
                    Some(result_id),
                    Vec::new(),
                    1,
                    Vec::new(),
                    Vec::new(),
                    retries,
                    provider_errors,
                    projection_for_error(error.kind),
                    None,
                ));
            }
        };
        self.validate_get_response(&request, &response, expected.as_ref())?;
        let projection = ResultProjection::Complete;
        Ok(self.finish_evidence(
            ReadOperation::Get,
            Some(result_id),
            vec![response.record],
            1,
            Vec::new(),
            vec![response.response_digest],
            retries,
            provider_errors,
            projection,
            None,
        ))
    }

    pub fn get(
        &mut self,
        result_id: crate::ResultId,
        expected: Option<ResultVersionFence>,
    ) -> Result<GcpRecommenderEvidence, GcpRecommenderServiceError> {
        self.read_get(result_id, expected)
    }

    pub fn propose(&mut self) -> Result<GcpRecommenderProposal, GcpRecommenderServiceError> {
        self.propose_list()
    }

    pub fn propose_list(&mut self) -> Result<GcpRecommenderProposal, GcpRecommenderServiceError> {
        let evidence = self.read_list()?;
        Ok(self.make_proposal(evidence))
    }

    pub fn propose_get(
        &mut self,
        result_id: crate::ResultId,
        expected: Option<ResultVersionFence>,
    ) -> Result<GcpRecommenderProposal, GcpRecommenderServiceError> {
        let evidence = self.read_get(result_id, expected)?;
        Ok(self.make_proposal(evidence))
    }

    pub fn verify(
        &self,
        proposal: &GcpRecommenderProposal,
    ) -> Result<(), GcpRecommenderServiceError> {
        self.ensure_ready(proposal.operation)?;
        if proposal.contract_version != GCP_RECOMMENDER_RESULT_CONTRACT_VERSION
            || proposal.contract_digest != crate::contract_digest()
            || proposal.plugin_version != GCP_RECOMMENDER_RESULT_PLUGIN_VERSION
            || proposal.registration_digest != self.registration.registration_digest
            || proposal.registration_revision != self.registration.registration_revision
            || proposal.scope_digest != self.scope.digest()
            || proposal.query_digest != self.query.digest()
            || proposal.filter_digest != self.query.filters().digest()
            || proposal.provider_digest != self.provider.definition().provider_digest()
            || !proposal.proposal_only
            || !proposal.read_only
            || proposal.native
            || proposal.connected
            || proposal.first_party
            || proposal.marks_recommendation
            || proposal.executes_operation_group
            || proposal.adopts_outcome
            || proposal.operation != proposal.evidence.operation
            || proposal.result_id != proposal.evidence.result_id
        {
            return Err(GcpRecommenderServiceError::FenceMismatch);
        }
        if proposal.evidence.scope_digest != self.scope.digest()
            || proposal.evidence.permission_digest != self.scope.permission().digest()
            || proposal.evidence.consent_digest != self.scope.consent().digest()
            || proposal.evidence.query_digest != self.query.digest()
            || proposal.evidence.filter_digest != self.query.filters().digest()
            || proposal.evidence.registration_digest != self.registration.registration_digest
            || proposal.evidence.provider_digest != self.provider.definition().provider_digest()
            || proposal.evidence.result_kind != *self.scope.result_kind()
            || proposal.evidence.provider_provenance != self.provider.provenance()
        {
            return Err(GcpRecommenderServiceError::FenceMismatch);
        }
        if proposal.evidence.records.len() > self.query.max_results() as usize
            || proposal.evidence.page_count > self.query.max_pages()
            || proposal.evidence.provider_provenance.is_native()
            || proposal.evidence.provider_provenance.is_connected()
            || proposal.evidence.provider_provenance.is_first_party()
        {
            return Err(GcpRecommenderServiceError::BoundExceeded);
        }
        for record in &proposal.evidence.records {
            self.validate_record(record)?;
            if !self.query.filters().matches(record) {
                return Err(GcpRecommenderServiceError::FilterMismatch);
            }
        }
        proposal.evidence.validate_digest()?;
        proposal.validate_digest()
    }

    pub fn verify_proposal(
        &self,
        proposal: &GcpRecommenderProposal,
    ) -> Result<(), GcpRecommenderServiceError> {
        self.verify(proposal)
    }

    pub fn record(
        &self,
        proposal: &GcpRecommenderProposal,
    ) -> Result<GcpRecommenderObservationReceipt, GcpRecommenderServiceError> {
        self.verify(proposal)?;
        let receipt_digest = Digest::from_fields(
            "gcp-recommender-observation-receipt/v1",
            &[
                proposal.proposal_digest.as_str().to_owned(),
                proposal.evidence.evidence_digest.as_str().to_owned(),
                self.registration.registration_digest.as_str().to_owned(),
                format!("{:?}", proposal.evidence.projection),
                format!("{:?}", proposal.evidence.provider_provenance),
                "durable=false".to_owned(),
                "connected=false".to_owned(),
                "native=false".to_owned(),
            ],
        );
        Ok(GcpRecommenderObservationReceipt {
            receipt_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            registration_digest: self.registration.registration_digest.clone(),
            projection: proposal.evidence.projection,
            provenance: proposal.evidence.provider_provenance,
            recorded: true,
            durable: false,
            connected: false,
            native: false,
            independent_native_readback: false,
            adopts_outcome: false,
        })
    }

    pub fn record_receipt(
        &self,
        proposal: &GcpRecommenderProposal,
    ) -> Result<GcpRecommenderObservationReceipt, GcpRecommenderServiceError> {
        self.record(proposal)
    }

    pub fn read_back(
        &self,
        proposal: &GcpRecommenderProposal,
    ) -> Result<GcpRecommenderReadbackReceipt, GcpRecommenderServiceError> {
        self.verify(proposal)?;
        let receipt_digest = Digest::from_fields(
            "gcp-recommender-readback-receipt/v1",
            &[
                proposal.proposal_digest.as_str().to_owned(),
                proposal.evidence.evidence_digest.as_str().to_owned(),
                "independent_native_readback=false".to_owned(),
            ],
        );
        Ok(GcpRecommenderReadbackReceipt {
            receipt_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            verified_against_proposal: true,
            independent_native_readback: false,
            connected: false,
            native: false,
        })
    }

    fn make_proposal(&self, evidence: GcpRecommenderEvidence) -> GcpRecommenderProposal {
        GcpRecommenderProposal::new(
            &self.registration,
            &self.scope,
            &self.query,
            self.provider.definition().provider_digest(),
            evidence,
        )
    }

    fn ensure_ready(&self, operation: ReadOperation) -> Result<(), GcpRecommenderServiceError> {
        self.service_definition.validate()?;
        self.scope.validate()?;
        self.query
            .validate_against(&self.scope)
            .map_err(|error| match error {
                ModelError::MissingReadPermission => {
                    GcpRecommenderServiceError::MissingReadPermission
                }
                ModelError::InvalidFilter => GcpRecommenderServiceError::QueryMismatch,
                other => GcpRecommenderServiceError::Model(other),
            })?;
        if !self
            .scope
            .permission()
            .allows(self.scope.result_kind().clone(), operation)
        {
            return Err(GcpRecommenderServiceError::MissingReadPermission);
        }
        if self.scope.consent().validate().is_err() {
            return Err(GcpRecommenderServiceError::ConsentMismatch);
        }
        if self.secret.is_revoked() {
            return Err(GcpRecommenderServiceError::SecretRevoked);
        }
        if self.secret.scope_digest() != self.scope.scope_digest() {
            return Err(GcpRecommenderServiceError::ScopeMismatch);
        }
        self.registration
            .ensure_active()
            .map_err(|_| GcpRecommenderServiceError::RegistrationRevoked)?;
        self.registration
            .validate(
                &self.scope,
                &self.query,
                self.provider.definition().provider_id.as_str(),
                &self.provider.definition().provider_version,
                &self.provider.definition().api_version,
                &self.provider.definition().provider_digest(),
                &self.secret.digest(),
                &evidence_policy_digest(),
            )
            .map_err(|_| GcpRecommenderServiceError::RegistrationRevoked)
    }

    fn list_request(
        &self,
        page_number: u8,
        page_token: Option<crate::OpaquePageToken>,
    ) -> GcpRecommenderListRequest {
        GcpRecommenderListRequest::from_scope(
            &self.scope,
            &self.query,
            &self.secret,
            page_number,
            page_token,
        )
    }

    fn get_request(
        &self,
        result_id: crate::ResultId,
        expected: Option<ResultVersionFence>,
    ) -> GcpRecommenderGetRequest {
        GcpRecommenderGetRequest::from_scope(
            &self.scope,
            &self.query,
            &self.secret,
            result_id,
            expected,
        )
    }

    fn call_list(
        &mut self,
        request: &GcpRecommenderListRequest,
        retries: &mut Vec<RetryEvidence>,
        provider_errors: &mut Vec<ProviderErrorEvidence>,
    ) -> Result<GcpRecommenderListResponse, TransportError> {
        for attempt in 1..=self.retry_policy.max_attempts() {
            match self.provider.list(request) {
                Ok(response) => return Ok(response),
                Err(error) if error.retryable && attempt < self.retry_policy.max_attempts() => {
                    retries.push(RetryEvidence {
                        operation: "recommender.list".to_owned(),
                        failed_attempt: attempt,
                        delay_seconds: self.retry_policy.delay_seconds(attempt, None),
                        kind: error.kind,
                        status_code: error.status_code,
                        diagnostic_digest: error.diagnostic_digest().clone(),
                    });
                }
                Err(error) => {
                    provider_errors.push(ProviderErrorEvidence::new(
                        error.kind,
                        error.status_code,
                        error.retryable,
                        attempt,
                        error.blocked_env,
                        error.diagnostic_digest().clone(),
                    ));
                    return Err(error);
                }
            }
        }
        unreachable!("bounded list retry loop always returns")
    }

    fn call_get(
        &mut self,
        request: &GcpRecommenderGetRequest,
        retries: &mut Vec<RetryEvidence>,
        provider_errors: &mut Vec<ProviderErrorEvidence>,
    ) -> Result<GcpRecommenderGetResponse, TransportError> {
        for attempt in 1..=self.retry_policy.max_attempts() {
            match self.provider.get(request) {
                Ok(response) => return Ok(response),
                Err(error) if error.retryable && attempt < self.retry_policy.max_attempts() => {
                    retries.push(RetryEvidence {
                        operation: "recommender.get".to_owned(),
                        failed_attempt: attempt,
                        delay_seconds: self.retry_policy.delay_seconds(attempt, None),
                        kind: error.kind,
                        status_code: error.status_code,
                        diagnostic_digest: error.diagnostic_digest().clone(),
                    });
                }
                Err(error) => {
                    provider_errors.push(ProviderErrorEvidence::new(
                        error.kind,
                        error.status_code,
                        error.retryable,
                        attempt,
                        error.blocked_env,
                        error.diagnostic_digest().clone(),
                    ));
                    return Err(error);
                }
            }
        }
        unreachable!("bounded get retry loop always returns")
    }

    fn validate_list_response(
        &self,
        request: &GcpRecommenderListRequest,
        response: &GcpRecommenderListResponse,
    ) -> Result<(), GcpRecommenderServiceError> {
        if !request.is_allowlisted() {
            return Err(GcpRecommenderServiceError::QueryMismatch);
        }
        response
            .validate_digest()
            .map_err(|_| GcpRecommenderServiceError::TamperedEvidence)?;
        if response.page_number != request.page_number
            || response.requested_page_token_digest != request.page_token_digest()
            || response.observed_scope_digest != request.scope_digest
            || response.observed_query_digest != request.query_digest
            || response.observed_filter_digest != request.filter_digest
            || response.observed_permission_digest != request.permission_digest
            || response.observed_consent_digest != request.consent_digest
            || response.observed_project_revision != request.project_revision
            || response.observed_mission_revision != request.mission_revision
            || response.observed_work_product_revision != request.work_product_revision
            || response.observed_credential_revision != request.credential_revision
            || response.next_page_token_digest
                != response
                    .next_page_token
                    .as_ref()
                    .map(crate::OpaquePageToken::digest)
        {
            return Err(GcpRecommenderServiceError::FenceMismatch);
        }
        for record in &response.records {
            self.validate_record(record)?;
            if !self.query.filters().matches(record) {
                return Err(GcpRecommenderServiceError::FilterMismatch);
            }
        }
        Ok(())
    }

    fn validate_get_response(
        &self,
        request: &GcpRecommenderGetRequest,
        response: &GcpRecommenderGetResponse,
        expected: Option<&ResultVersionFence>,
    ) -> Result<(), GcpRecommenderServiceError> {
        if !request.is_allowlisted() {
            return Err(GcpRecommenderServiceError::QueryMismatch);
        }
        response
            .validate_digest()
            .map_err(|_| GcpRecommenderServiceError::TamperedEvidence)?;
        if response.observed_scope_digest != request.scope_digest
            || response.observed_query_digest != request.query_digest
            || response.observed_filter_digest != request.filter_digest
            || response.observed_permission_digest != request.permission_digest
            || response.observed_consent_digest != request.consent_digest
            || response.observed_project_revision != request.project_revision
            || response.observed_mission_revision != request.mission_revision
            || response.observed_work_product_revision != request.work_product_revision
            || response.observed_credential_revision != request.credential_revision
            || response.record.result_id != request.result_id
        {
            return Err(GcpRecommenderServiceError::FenceMismatch);
        }
        self.validate_record(&response.record)?;
        if !self.query.filters().matches(&response.record) {
            return Err(GcpRecommenderServiceError::FilterMismatch);
        }
        if let Some(expected) = expected {
            if response.record.etag_digest != expected.etag_digest {
                return Err(GcpRecommenderServiceError::EtagDrift);
            }
            if response.record.revision != expected.revision {
                return Err(GcpRecommenderServiceError::RevisionDrift);
            }
        }
        Ok(())
    }

    fn validate_record(
        &self,
        record: &GcpRecommenderRecord,
    ) -> Result<(), GcpRecommenderServiceError> {
        record
            .validate_digest()
            .map_err(|_| GcpRecommenderServiceError::TamperedEvidence)?;
        if record.result_kind != *self.scope.result_kind() {
            return Err(GcpRecommenderServiceError::ScopeMismatch);
        }
        if record
            .target_resource_fingerprints
            .iter()
            .any(|fingerprint| {
                !self
                    .scope
                    .target_resource_fingerprints()
                    .contains(fingerprint)
            })
        {
            return Err(GcpRecommenderServiceError::TargetOutOfScope);
        }
        Ok(())
    }

    fn finish_evidence(
        &self,
        operation: ReadOperation,
        result_id: Option<crate::ResultId>,
        records: Vec<GcpRecommenderRecord>,
        page_count: u8,
        page_token_digests: Vec<Digest>,
        response_digests: Vec<Digest>,
        retries: Vec<RetryEvidence>,
        provider_errors: Vec<ProviderErrorEvidence>,
        projection: ResultProjection,
        partial_reason: Option<PartialReason>,
    ) -> GcpRecommenderEvidence {
        GcpRecommenderEvidence::new(
            &self.scope,
            &self.query,
            &self.registration,
            self.provider.definition().provider_digest(),
            operation,
            result_id,
            records,
            page_count,
            page_token_digests,
            response_digests,
            retries,
            provider_errors,
            projection,
            partial_reason,
            self.provider.provenance(),
        )
    }
}

impl SecretReference {
    fn validate_scope(
        &self,
        scope: &GcpRecommenderScope,
    ) -> Result<(), GcpRecommenderServiceError> {
        if self.is_revoked() {
            Err(GcpRecommenderServiceError::SecretRevoked)
        } else if self.scope_digest() != scope.scope_digest() {
            Err(GcpRecommenderServiceError::ScopeMismatch)
        } else {
            Ok(())
        }
    }
}

fn projection_for_error(kind: ProviderErrorKind) -> ResultProjection {
    match kind {
        ProviderErrorKind::Unauthenticated | ProviderErrorKind::PermissionDenied => {
            ResultProjection::AccessLost
        }
        ProviderErrorKind::RateLimited => ResultProjection::RateLimited,
        ProviderErrorKind::BlockedEnv => ResultProjection::BlockedEnv,
        ProviderErrorKind::BadRequest
        | ProviderErrorKind::Conflict
        | ProviderErrorKind::NotFound
        | ProviderErrorKind::EtagDrift
        | ProviderErrorKind::RevisionDrift
        | ProviderErrorKind::ScopeMismatch
        | ProviderErrorKind::FilterMismatch
        | ProviderErrorKind::Tampered
        | ProviderErrorKind::Truncated => ResultProjection::FinalError,
        ProviderErrorKind::ServerFailure
        | ProviderErrorKind::Timeout
        | ProviderErrorKind::Unknown => ResultProjection::ProviderUnknown,
    }
}
