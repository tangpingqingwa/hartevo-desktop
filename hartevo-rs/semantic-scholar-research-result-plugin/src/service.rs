use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    ApiHost, ApiKeyPermission, ApiVersion, AuthorMetadata, CitationRecord, ConsentDataClass,
    Digest, EndpointKind, Layer1Authority, ModelError, NativeTransportProvenance, OpaqueCursor,
    PaperMetadata, PluginVersion, RecommendationRecord, RegistrationState, ResearchQuery,
    ResearchResultStatus, RetryEvidence, RetryPolicy, Revision, SecretReference,
    SemanticScholarScope,
};
use crate::provider::{
    ApiGetRequest, ProviderError, ProviderProvenance, SemanticScholarProvider,
    SemanticScholarProviderDefinition, SemanticScholarResponse, SemanticScholarTransport,
    TransportError,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ServiceError {
    #[error("model validation failed: {0}")]
    Model(#[from] ModelError),
    #[error("provider failed: {0}")]
    Provider(#[from] ProviderError),
    #[error("a query must be registered before proposal compilation")]
    RegistrationRequired,
    #[error("the Semantic Scholar registration is revoked")]
    RegistrationRevoked,
    #[error("the expected registration digest or revision does not match")]
    RegistrationMismatch,
    #[error("the query does not match the registered query digest or revision")]
    QueryMismatch,
    #[error("the SecretReference does not match the registered scope or permission")]
    SecretMismatch,
    #[error("the provider returned a record outside the registered paper/author/venue scope")]
    ScopeMismatch,
    #[error("the provider returned a duplicate record across bounded pages")]
    DuplicateRecord,
    #[error("the bounded cursor repeated before the provider marked the response complete")]
    CursorLoop,
    #[error("the response exceeded the aggregate Layer-1 bound")]
    AggregateResponseTooLarge,
    #[error("the result exceeded the Layer-1 record bound")]
    ResultBoundExceeded,
    #[error("the proposal or evidence digest is tampered")]
    ProposalTampered,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticScholarOperation {
    DescribeCapabilities,
    Register,
    RevokeRegistration,
    RevokeSecret,
    CompileBoundedGetProposal,
    RecordRedactedResultEvidence,
    ConsumeMissionResult,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SemanticScholarResearchResultServiceDefinition {
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub contract_version: String,
    pub plugin_version: PluginVersion,
    pub operations: Vec<SemanticScholarOperation>,
    pub read_only: bool,
    pub live_external_io: bool,
    pub connected_authority: bool,
    pub truth_authority: bool,
    pub work_product_adoption: bool,
}

impl SemanticScholarResearchResultServiceDefinition {
    #[must_use]
    pub fn layer1() -> Self {
        Self {
            service_id: String::from(crate::SEMANTIC_SCHOLAR_SERVICE_ID),
            provider_id: String::from(crate::SEMANTIC_SCHOLAR_PROVIDER_ID),
            consumer_id: String::from(crate::MISSION_SEMANTIC_SCHOLAR_CONSUMER_ID),
            contract_version: String::from(crate::SEMANTIC_SCHOLAR_CONTRACT_VERSION),
            plugin_version: PluginVersion::V1,
            operations: vec![
                SemanticScholarOperation::DescribeCapabilities,
                SemanticScholarOperation::Register,
                SemanticScholarOperation::RevokeRegistration,
                SemanticScholarOperation::RevokeSecret,
                SemanticScholarOperation::CompileBoundedGetProposal,
                SemanticScholarOperation::RecordRedactedResultEvidence,
                SemanticScholarOperation::ConsumeMissionResult,
            ],
            read_only: true,
            live_external_io: false,
            connected_authority: false,
            truth_authority: false,
            work_product_adoption: false,
        }
    }

    pub fn validate(&self) -> Result<(), ServiceError> {
        if self.service_id != crate::SEMANTIC_SCHOLAR_SERVICE_ID
            || self.provider_id != crate::SEMANTIC_SCHOLAR_PROVIDER_ID
            || self.consumer_id != crate::MISSION_SEMANTIC_SCHOLAR_CONSUMER_ID
            || self.contract_version != crate::SEMANTIC_SCHOLAR_CONTRACT_VERSION
            || self.plugin_version != PluginVersion::V1
            || self.operations.len() != 7
            || !self.read_only
            || self.live_external_io
            || self.connected_authority
            || self.truth_authority
            || self.work_product_adoption
        {
            return Err(ServiceError::ProposalTampered);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<Digest, ServiceError> {
        Ok(Digest::from_serializable(self)?)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SemanticScholarRegistration {
    pub plugin_version: PluginVersion,
    pub contract_version: String,
    pub contract_digest: Digest,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_digest: Digest,
    pub api_host: ApiHost,
    pub api_version: ApiVersion,
    pub api_key_permission: ApiKeyPermission,
    pub secret_reference_digest: Digest,
    pub credential_revision: Revision,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub query_digest: Digest,
    pub query_kind: crate::QueryKind,
    pub query_revision: Revision,
    pub paper_scope_digest: Digest,
    pub author_scope_digest: Digest,
    pub venue_scope_digest: Digest,
    pub mission_id: crate::MissionId,
    pub mission_revision: Revision,
    pub project_id: crate::ProjectId,
    pub project_revision: Revision,
    pub work_product_id: crate::WorkProductId,
    pub work_product_revision: Revision,
    pub revision: Revision,
    pub state: RegistrationState,
    pub registration_digest: Digest,
}

impl SemanticScholarRegistration {
    pub fn new<T: SemanticScholarTransport>(
        scope: &SemanticScholarScope,
        secret: &SecretReference,
        provider: &SemanticScholarProvider<T>,
        query: &ResearchQuery,
        revision: Revision,
    ) -> Result<Self, ServiceError> {
        if secret.is_revoked()
            || secret.scope_digest() != scope.scope_digest()
            || secret.permission() != scope.api_key_permission()
        {
            return Err(ServiceError::SecretMismatch);
        }
        query.validate(scope)?;
        let query_digest = query.digest()?;
        let definition = provider.definition();
        let contract_digest = crate::contract_digest();
        let mut registration = Self {
            plugin_version: PluginVersion::V1,
            contract_version: String::from(crate::SEMANTIC_SCHOLAR_CONTRACT_VERSION),
            contract_digest,
            provider_id: definition.provider_id.clone(),
            provider_version: definition.provider_version.clone(),
            provider_digest: definition.capability_digest.clone(),
            api_host: scope.api_host(),
            api_version: scope.api_version(),
            api_key_permission: scope.api_key_permission(),
            secret_reference_digest: secret.reference_digest().clone(),
            credential_revision: secret.credential_revision(),
            scope_digest: scope.scope_digest().clone(),
            permission_digest: scope.permission_digest().clone(),
            consent_digest: scope.consent().consent_digest().clone(),
            query_digest,
            query_kind: query.kind(),
            query_revision: query.query_revision(),
            paper_scope_digest: scope.paper_scope_digest().clone(),
            author_scope_digest: scope.author_scope_digest().clone(),
            venue_scope_digest: scope.venue_scope_digest().clone(),
            mission_id: scope.mission_id().clone(),
            mission_revision: scope.mission_revision(),
            project_id: scope.project_id().clone(),
            project_revision: scope.project_revision(),
            work_product_id: scope.work_product_id().clone(),
            work_product_revision: scope.work_product_revision(),
            revision,
            state: RegistrationState::Active,
            registration_digest: Digest::from_text("registration-placeholder"),
        };
        registration.registration_digest = registration.compute_digest()?;
        Ok(registration)
    }

    fn compute_digest(&self) -> Result<Digest, ModelError> {
        Digest::from_serializable(&RegistrationIdentity {
            plugin_version: self.plugin_version,
            contract_version: &self.contract_version,
            contract_digest: &self.contract_digest,
            provider_id: &self.provider_id,
            provider_version: &self.provider_version,
            provider_digest: &self.provider_digest,
            api_host: self.api_host,
            api_version: self.api_version,
            api_key_permission: self.api_key_permission,
            secret_reference_digest: &self.secret_reference_digest,
            credential_revision: self.credential_revision,
            scope_digest: &self.scope_digest,
            permission_digest: &self.permission_digest,
            consent_digest: &self.consent_digest,
            query_digest: &self.query_digest,
            query_kind: self.query_kind,
            query_revision: self.query_revision,
            paper_scope_digest: &self.paper_scope_digest,
            author_scope_digest: &self.author_scope_digest,
            venue_scope_digest: &self.venue_scope_digest,
            mission_id: &self.mission_id,
            mission_revision: self.mission_revision,
            project_id: &self.project_id,
            project_revision: self.project_revision,
            work_product_id: &self.work_product_id,
            work_product_revision: self.work_product_revision,
            revision: self.revision,
        })
    }

    pub fn validate(&self) -> Result<(), ServiceError> {
        let provider_definition =
            SemanticScholarProviderDefinition::layer1(self.provider_version.clone())?;
        if self.plugin_version != PluginVersion::V1
            || self.contract_version != crate::SEMANTIC_SCHOLAR_CONTRACT_VERSION
            || self.provider_id != crate::SEMANTIC_SCHOLAR_PROVIDER_ID
            || self.api_host != ApiHost::SemanticScholar
            || self.api_version != ApiVersion::V1
            || self.contract_digest != crate::contract_digest()
            || !self.contract_digest.is_valid()
            || self.provider_digest != *provider_definition.digest()
            || !self.secret_reference_digest.is_valid()
            || !self.scope_digest.is_valid()
            || !self.permission_digest.is_valid()
            || !self.consent_digest.is_valid()
            || !self.query_digest.is_valid()
            || !self.paper_scope_digest.is_valid()
            || !self.author_scope_digest.is_valid()
            || !self.venue_scope_digest.is_valid()
            || self.registration_digest != self.compute_digest()?
        {
            return Err(ServiceError::ProposalTampered);
        }
        Ok(())
    }

    pub fn revoke(&mut self) -> Result<(), ServiceError> {
        if self.state == RegistrationState::Revoked {
            return Err(ServiceError::RegistrationRevoked);
        }
        self.state = RegistrationState::Revoked;
        Ok(())
    }

    pub fn ensure_active(&self) -> Result<(), ServiceError> {
        if self.state == RegistrationState::Active {
            Ok(())
        } else {
            Err(ServiceError::RegistrationRevoked)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistrationIdentity<'a> {
    plugin_version: PluginVersion,
    contract_version: &'a str,
    contract_digest: &'a Digest,
    provider_id: &'a str,
    provider_version: &'a str,
    provider_digest: &'a Digest,
    api_host: ApiHost,
    api_version: ApiVersion,
    api_key_permission: ApiKeyPermission,
    secret_reference_digest: &'a Digest,
    credential_revision: Revision,
    scope_digest: &'a Digest,
    permission_digest: &'a Digest,
    consent_digest: &'a Digest,
    query_digest: &'a Digest,
    query_kind: crate::QueryKind,
    query_revision: Revision,
    paper_scope_digest: &'a Digest,
    author_scope_digest: &'a Digest,
    venue_scope_digest: &'a Digest,
    mission_id: &'a crate::MissionId,
    mission_revision: Revision,
    project_id: &'a crate::ProjectId,
    project_revision: Revision,
    work_product_id: &'a crate::WorkProductId,
    work_product_revision: Revision,
    revision: Revision,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SemanticScholarResearchProposalRequest {
    pub query: ResearchQuery,
    pub expected_registration_digest: Digest,
    pub expected_registration_revision: Revision,
}

impl SemanticScholarResearchProposalRequest {
    pub fn new(query: ResearchQuery, registration: &SemanticScholarRegistration) -> Self {
        Self {
            query,
            expected_registration_digest: registration.registration_digest.clone(),
            expected_registration_revision: registration.revision,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RequestReceipt {
    pub endpoint: EndpointKind,
    pub path: String,
    pub page_index: u16,
    pub query_digest: Digest,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub request_digest: Digest,
    pub response_digest: Option<Digest>,
    pub response_bytes: Option<usize>,
    pub credential_revision: Revision,
    pub provenance: ProviderProvenance,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SemanticScholarResearchResultEvidence {
    pub status: ResearchResultStatus,
    pub provenance: ProviderProvenance,
    pub query_digest: Digest,
    pub query_revision: Revision,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub request_receipts: Vec<RequestReceipt>,
    pub response_digests: Vec<Digest>,
    pub response_digest: Digest,
    pub papers: Vec<PaperMetadata>,
    pub authors: Vec<AuthorMetadata>,
    pub citations: Vec<CitationRecord>,
    pub references: Vec<CitationRecord>,
    pub recommendations: Vec<RecommendationRecord>,
    pub retry: RetryEvidence,
    pub provider_error: Option<crate::ProviderErrorEvidence>,
    pub redactions: Vec<crate::RedactionNotice>,
    pub result_digest: Digest,
}

impl SemanticScholarResearchResultEvidence {
    fn compute_digest(&self) -> Result<Digest, ModelError> {
        Digest::from_serializable(&EvidenceIdentity {
            status: self.status,
            provenance: self.provenance,
            query_digest: &self.query_digest,
            query_revision: self.query_revision,
            scope_digest: &self.scope_digest,
            permission_digest: &self.permission_digest,
            consent_digest: &self.consent_digest,
            registration_digest: &self.registration_digest,
            provider_digest: &self.provider_digest,
            request_receipts: &self.request_receipts,
            response_digests: &self.response_digests,
            response_digest: &self.response_digest,
            papers: &self.papers,
            authors: &self.authors,
            citations: &self.citations,
            references: &self.references,
            recommendations: &self.recommendations,
            retry: &self.retry,
            provider_error: &self.provider_error,
            redactions: &self.redactions,
        })
    }

    pub fn validate(&self) -> Result<(), ServiceError> {
        if !self.query_digest.is_valid()
            || !self.scope_digest.is_valid()
            || !self.permission_digest.is_valid()
            || !self.consent_digest.is_valid()
            || !self.registration_digest.is_valid()
            || !self.provider_digest.is_valid()
            || !self.response_digest.is_valid()
            || self.result_digest != self.compute_digest()?
        {
            return Err(ServiceError::ProposalTampered);
        }
        for paper in &self.papers {
            paper.validate()?;
        }
        for author in &self.authors {
            author.validate()?;
        }
        for citation in self.citations.iter().chain(&self.references) {
            citation.validate()?;
        }
        for recommendation in &self.recommendations {
            recommendation.validate()?;
        }
        Ok(())
    }
}

pub type SemanticScholarResearchEvidence = SemanticScholarResearchResultEvidence;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EvidenceIdentity<'a> {
    status: ResearchResultStatus,
    provenance: ProviderProvenance,
    query_digest: &'a Digest,
    query_revision: Revision,
    scope_digest: &'a Digest,
    permission_digest: &'a Digest,
    consent_digest: &'a Digest,
    registration_digest: &'a Digest,
    provider_digest: &'a Digest,
    request_receipts: &'a [RequestReceipt],
    response_digests: &'a [Digest],
    response_digest: &'a Digest,
    papers: &'a [PaperMetadata],
    authors: &'a [AuthorMetadata],
    citations: &'a [CitationRecord],
    references: &'a [CitationRecord],
    recommendations: &'a [RecommendationRecord],
    retry: &'a RetryEvidence,
    provider_error: &'a Option<crate::ProviderErrorEvidence>,
    redactions: &'a [crate::RedactionNotice],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticScholarResearchResultProposal {
    pub query: ResearchQuery,
    pub registration_digest: Digest,
    pub registration_revision: Revision,
    pub evidence: SemanticScholarResearchResultEvidence,
    pub proposal_digest: Digest,
    pub authority: Layer1Authority,
}

impl SemanticScholarResearchResultProposal {
    fn compute_digest(&self) -> Result<Digest, ModelError> {
        Digest::from_serializable(&(
            &self.query,
            &self.registration_digest,
            self.registration_revision,
            &self.evidence.result_digest,
        ))
    }

    pub fn validate(&self) -> Result<(), ServiceError> {
        self.evidence.validate()?;
        if !self.registration_digest.is_valid()
            || self.evidence.registration_digest != self.registration_digest
            || self.evidence.query_digest != self.query.logical_digest()?
            || self.proposal_digest != self.compute_digest()?
        {
            return Err(ServiceError::ProposalTampered);
        }
        Ok(())
    }

    #[must_use]
    pub const fn connected(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn native(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn truth_authority(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn adopted(&self) -> bool {
        false
    }
}

pub type SemanticScholarResearchResult = SemanticScholarResearchResultProposal;

/// Standalone Layer-1 service. It owns proposal compilation and bounded
/// recording seams, not credential resolution, native I/O, or adoption.
pub struct SemanticScholarResearchResultService<
    T: SemanticScholarTransport = crate::RecordingSemanticScholarTransport,
> {
    scope: SemanticScholarScope,
    secret: SecretReference,
    provider: SemanticScholarProvider<T>,
    definition: SemanticScholarResearchResultServiceDefinition,
    registration: Option<SemanticScholarRegistration>,
    retry_policy: RetryPolicy,
}

impl<T: SemanticScholarTransport> fmt::Debug for SemanticScholarResearchResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SemanticScholarResearchResultService")
            .field("scope_digest", self.scope.scope_digest())
            .field("secret", &self.secret)
            .field("provider", &self.provider)
            .field("definition", &self.definition)
            .field("registration", &self.registration)
            .field("retry_policy", &self.retry_policy)
            .finish()
    }
}

impl<T: SemanticScholarTransport> SemanticScholarResearchResultService<T> {
    pub fn new(
        scope: SemanticScholarScope,
        secret: SecretReference,
        provider: SemanticScholarProvider<T>,
    ) -> Result<Self, ServiceError> {
        if secret.scope_digest() != scope.scope_digest()
            || secret.permission() != scope.api_key_permission()
        {
            return Err(ServiceError::SecretMismatch);
        }
        let definition = SemanticScholarResearchResultServiceDefinition::layer1();
        definition.validate()?;
        Ok(Self {
            scope,
            secret,
            provider,
            definition,
            registration: None,
            retry_policy: RetryPolicy::default(),
        })
    }

    #[must_use]
    pub fn with_retry_policy(mut self, retry_policy: RetryPolicy) -> Self {
        self.retry_policy = retry_policy;
        self
    }

    #[must_use]
    pub fn definition(&self) -> &SemanticScholarResearchResultServiceDefinition {
        &self.definition
    }

    #[must_use]
    pub fn scope(&self) -> &SemanticScholarScope {
        &self.scope
    }

    #[must_use]
    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret
    }

    #[must_use]
    pub fn provider(&self) -> &SemanticScholarProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut SemanticScholarProvider<T> {
        &mut self.provider
    }

    #[must_use]
    pub fn registration(&self) -> Option<&SemanticScholarRegistration> {
        self.registration.as_ref()
    }

    pub fn register(
        &mut self,
        query: ResearchQuery,
    ) -> Result<&SemanticScholarRegistration, ServiceError> {
        if self.secret.is_revoked() {
            return Err(ServiceError::SecretMismatch);
        }
        let next_revision = self
            .registration
            .as_ref()
            .map_or(1, |registration| registration.revision.get() + 1);
        let registration = SemanticScholarRegistration::new(
            &self.scope,
            &self.secret,
            &self.provider,
            &query,
            Revision::new(next_revision)?,
        )?;
        self.registration = Some(registration);
        Ok(self
            .registration
            .as_ref()
            .expect("registration just stored"))
    }

    pub fn register_query(
        &mut self,
        query: ResearchQuery,
    ) -> Result<&SemanticScholarRegistration, ServiceError> {
        self.register(query)
    }

    pub fn revoke_registration(&mut self) -> Result<(), ServiceError> {
        self.registration_mut()?.revoke()
    }

    pub fn revoke_secret(&mut self) -> Result<(), ServiceError> {
        self.secret.revoke().map_err(ServiceError::from)
    }

    pub fn propose(
        &mut self,
        request: SemanticScholarResearchProposalRequest,
    ) -> Result<SemanticScholarResearchResultProposal, ServiceError> {
        let registration = self
            .registration
            .clone()
            .ok_or(ServiceError::RegistrationRequired)?;
        registration.validate()?;
        registration.ensure_active()?;
        if request.expected_registration_digest != registration.registration_digest
            || request.expected_registration_revision != registration.revision
        {
            return Err(ServiceError::RegistrationMismatch);
        }
        request.query.validate(&self.scope)?;
        if request.query.digest()? != registration.query_digest
            || request.query.kind() != registration.query_kind
            || request.query.query_revision() != registration.query_revision
        {
            return Err(ServiceError::QueryMismatch);
        }
        if self.secret.is_revoked()
            || self.secret.reference_digest() != &registration.secret_reference_digest
            || self.secret.credential_revision() != registration.credential_revision
        {
            return Err(ServiceError::SecretMismatch);
        }

        let mut accumulator = EvidenceAccumulator::new(
            &self.scope,
            &registration,
            self.provider.provenance(),
            self.retry_policy,
        );
        let mut query = request.query.clone();
        let mut seen_cursors = BTreeSet::new();
        let mut page_index = 0_u16;
        let mut forced_status = None;
        loop {
            if page_index >= crate::MAX_PAGES {
                accumulator.partial = true;
                break;
            }
            let api_request = ApiGetRequest::from_query(
                &query,
                &self.scope,
                registration.registration_digest.clone(),
                self.secret.credential_revision(),
            )?;
            match self.fetch_with_bounded_retry(&api_request, &mut accumulator.retry) {
                Ok(response) => {
                    accumulator.add_page(&query, &api_request, response, page_index)?;
                    page_index += 1;
                    if accumulator.complete {
                        break;
                    }
                    let Some(cursor) = accumulator.next_cursor().cloned() else {
                        accumulator.partial = true;
                        break;
                    };
                    if !seen_cursors.insert(cursor.clone()) {
                        return Err(ServiceError::CursorLoop);
                    }
                    query = query_with_cursor(&query, cursor)?;
                }
                Err(error) => {
                    accumulator.add_error_receipt(&api_request, page_index);
                    let (status, evidence) = normalized_provider_error(&error)?;
                    accumulator.provider_error = Some(evidence);
                    forced_status = Some(status);
                    break;
                }
            }
        }
        let evidence = accumulator.finish(forced_status)?;
        let proposal_digest = Digest::from_serializable(&(
            &request.query,
            &registration.registration_digest,
            registration.revision,
            &evidence.result_digest,
        ))?;
        let proposal = SemanticScholarResearchResultProposal {
            query: request.query,
            registration_digest: registration.registration_digest,
            registration_revision: registration.revision,
            evidence,
            proposal_digest,
            authority: Layer1Authority,
        };
        proposal.validate()?;
        Ok(proposal)
    }

    fn registration_mut(&mut self) -> Result<&mut SemanticScholarRegistration, ServiceError> {
        self.registration
            .as_mut()
            .ok_or(ServiceError::RegistrationRequired)
    }

    fn fetch_with_bounded_retry(
        &mut self,
        request: &ApiGetRequest,
        retry: &mut RetryEvidence,
    ) -> Result<SemanticScholarResponse, ProviderError> {
        let mut attempts = 0_u8;
        loop {
            attempts = attempts.saturating_add(1);
            retry.attempts = retry.attempts.saturating_add(1);
            match self.provider.get(request) {
                Ok(response) => return Ok(response),
                Err(ProviderError::Transport(TransportError::RateLimited {
                    retry_after_seconds,
                })) if attempts < self.retry_policy.max_attempts => {
                    retry.retry_after_seconds = retry_after_seconds;
                    retry.bounded_backoff_seconds = retry_after_seconds
                        .unwrap_or(0)
                        .min(self.retry_policy.max_backoff_seconds);
                }
                Err(error) => return Err(error),
            }
        }
    }
}

fn query_with_cursor(
    query: &ResearchQuery,
    cursor: OpaqueCursor,
) -> Result<ResearchQuery, ModelError> {
    let page =
        |page: &crate::PageRequest| crate::PageRequest::new(page.limit(), 0, Some(cursor.clone()));
    Ok(match query {
        ResearchQuery::PaperSearch {
            query,
            page: old_page,
            fields,
        } => ResearchQuery::PaperSearch {
            query: query.clone(),
            page: page(old_page)?,
            fields: fields.clone(),
        },
        ResearchQuery::PaperBulkSearch {
            query,
            page: old_page,
            fields,
        } => ResearchQuery::PaperBulkSearch {
            query: query.clone(),
            page: page(old_page)?,
            fields: fields.clone(),
        },
        ResearchQuery::PaperAuthors {
            paper_id,
            page: old_page,
            fields,
        } => ResearchQuery::PaperAuthors {
            paper_id: paper_id.clone(),
            page: page(old_page)?,
            fields: fields.clone(),
        },
        ResearchQuery::PaperCitations {
            paper_id,
            page: old_page,
            fields,
        } => ResearchQuery::PaperCitations {
            paper_id: paper_id.clone(),
            page: page(old_page)?,
            fields: fields.clone(),
        },
        ResearchQuery::PaperReferences {
            paper_id,
            page: old_page,
            fields,
        } => ResearchQuery::PaperReferences {
            paper_id: paper_id.clone(),
            page: page(old_page)?,
            fields: fields.clone(),
        },
        ResearchQuery::AuthorSearch {
            query,
            page: old_page,
            fields,
        } => ResearchQuery::AuthorSearch {
            query: query.clone(),
            page: page(old_page)?,
            fields: fields.clone(),
        },
        ResearchQuery::AuthorPapers {
            author_id,
            page: old_page,
            fields,
        } => ResearchQuery::AuthorPapers {
            author_id: author_id.clone(),
            page: page(old_page)?,
            fields: fields.clone(),
        },
        ResearchQuery::Recommendations {
            paper_id,
            page: old_page,
            pool,
            fields,
        } => ResearchQuery::Recommendations {
            paper_id: paper_id.clone(),
            page: page(old_page)?,
            pool: *pool,
            fields: fields.clone(),
        },
        ResearchQuery::PaperDetails { .. }
        | ResearchQuery::AuthorDetails { .. }
        | ResearchQuery::VenueMetadata { .. } => {
            return Err(ModelError::InvalidQuery {
                reason: "a non-paginated query returned a cursor",
            });
        }
    })
}

fn normalized_provider_error(
    error: &ProviderError,
) -> Result<(ResearchResultStatus, crate::ProviderErrorEvidence), ServiceError> {
    let (code, retry_after) = match error {
        ProviderError::Transport(TransportError::BlockedEnv) => ("BLOCKED_ENV", None),
        ProviderError::Transport(
            TransportError::Unauthorized | TransportError::Forbidden | TransportError::NotFound,
        ) => ("ACCESS_LOST", None),
        ProviderError::Transport(TransportError::RateLimited {
            retry_after_seconds,
        }) => ("RATE_LIMITED", *retry_after_seconds),
        ProviderError::Transport(TransportError::Timeout) => ("TIMEOUT", None),
        ProviderError::Transport(
            TransportError::BadRequest
            | TransportError::ResponseTooLarge
            | TransportError::MalformedResponse
            | TransportError::Unavailable
            | TransportError::ProviderUnknown,
        ) => ("PROVIDER_UNKNOWN", None),
        ProviderError::MethodNotAllowed
        | ProviderError::HostOrVersionMismatch
        | ProviderError::EndpointNotAllowlisted
        | ProviderError::ResponseTooLarge
        | ProviderError::ResponseTampered
        | ProviderError::ResponseKindMismatch
        | ProviderError::Model(_) => return Err(error.clone().into()),
    };
    let status = match code {
        "ACCESS_LOST" => ResearchResultStatus::AccessLost,
        "RATE_LIMITED" => ResearchResultStatus::RateLimited,
        _ => ResearchResultStatus::ProviderUnknown,
    };
    Ok((
        status,
        crate::ProviderErrorEvidence::new(code, retry_after)?,
    ))
}

struct EvidenceAccumulator {
    scope: SemanticScholarScope,
    registration: SemanticScholarRegistration,
    provenance: ProviderProvenance,
    retry_policy: RetryPolicy,
    request_receipts: Vec<RequestReceipt>,
    response_digests: Vec<Digest>,
    papers: Vec<PaperMetadata>,
    authors: Vec<AuthorMetadata>,
    citations: Vec<CitationRecord>,
    references: Vec<CitationRecord>,
    recommendations: Vec<RecommendationRecord>,
    seen_records: BTreeSet<Digest>,
    next_cursor: Option<OpaqueCursor>,
    response_bytes: usize,
    complete: bool,
    partial: bool,
    retry: RetryEvidence,
    provider_error: Option<crate::ProviderErrorEvidence>,
}

impl EvidenceAccumulator {
    fn new(
        scope: &SemanticScholarScope,
        registration: &SemanticScholarRegistration,
        provenance: ProviderProvenance,
        retry_policy: RetryPolicy,
    ) -> Self {
        Self {
            scope: scope.clone(),
            registration: registration.clone(),
            provenance,
            retry_policy,
            request_receipts: Vec::new(),
            response_digests: Vec::new(),
            papers: Vec::new(),
            authors: Vec::new(),
            citations: Vec::new(),
            references: Vec::new(),
            recommendations: Vec::new(),
            seen_records: BTreeSet::new(),
            next_cursor: None,
            response_bytes: 0,
            complete: false,
            partial: false,
            retry: RetryEvidence::default(),
            provider_error: None,
        }
    }

    fn add_page(
        &mut self,
        query: &ResearchQuery,
        request: &ApiGetRequest,
        response: SemanticScholarResponse,
        page_index: u16,
    ) -> Result<(), ServiceError> {
        self.response_bytes = self
            .response_bytes
            .checked_add(response.response_bytes())
            .ok_or(ServiceError::AggregateResponseTooLarge)?;
        if self.response_bytes > crate::MAX_RESPONSE_BYTES {
            return Err(ServiceError::AggregateResponseTooLarge);
        }
        self.response_digests
            .push(response.response_digest().clone());
        self.request_receipts.push(RequestReceipt {
            endpoint: request.endpoint(),
            path: request.path().to_owned(),
            page_index,
            query_digest: request.query_digest().clone(),
            scope_digest: request.scope_digest().clone(),
            registration_digest: request.registration_digest().clone(),
            request_digest: request.request_digest().clone(),
            response_digest: Some(response.response_digest().clone()),
            response_bytes: Some(response.response_bytes()),
            credential_revision: request.credential_revision(),
            provenance: self.provenance,
        });
        match response {
            SemanticScholarResponse::Paper(page) => {
                for paper in page.records {
                    self.add_paper(paper)?;
                }
                self.complete = page.complete;
                self.next_cursor = page.next_cursor;
            }
            SemanticScholarResponse::Author(page) => {
                for author in page.records {
                    if !self.scope.allows_author(&author.author_id) {
                        return Err(ServiceError::ScopeMismatch);
                    }
                    if !self.seen_records.insert(author.digest.clone()) {
                        return Err(ServiceError::DuplicateRecord);
                    }
                    self.authors.push(author);
                }
                self.complete = page.complete;
                self.next_cursor = page.next_cursor;
            }
            SemanticScholarResponse::Citation(page) => {
                let to_references = match query.kind() {
                    crate::QueryKind::PaperCitations => false,
                    crate::QueryKind::PaperReferences => true,
                    _ => return Err(ServiceError::Provider(ProviderError::ResponseKindMismatch)),
                };
                for citation in page.records {
                    self.add_citation(citation, to_references)?;
                }
                self.complete = page.complete;
                self.next_cursor = page.next_cursor;
            }
            SemanticScholarResponse::Recommendation(page) => {
                for recommendation in page.records {
                    self.add_paper(recommendation.paper.clone())?;
                    if !self
                        .seen_records
                        .insert(recommendation.recommendation_digest.clone())
                    {
                        return Err(ServiceError::DuplicateRecord);
                    }
                    self.recommendations.push(recommendation);
                }
                self.complete = page.complete;
                self.next_cursor = page.next_cursor;
            }
        }
        if self.record_count() > crate::MAX_RECORDS {
            return Err(ServiceError::ResultBoundExceeded);
        }
        if self.retry_policy.max_attempts == 0 {
            return Err(ServiceError::ProposalTampered);
        }
        Ok(())
    }

    fn add_error_receipt(&mut self, request: &ApiGetRequest, page_index: u16) {
        self.request_receipts.push(RequestReceipt {
            endpoint: request.endpoint(),
            path: request.path().to_owned(),
            page_index,
            query_digest: request.query_digest().clone(),
            scope_digest: request.scope_digest().clone(),
            registration_digest: request.registration_digest().clone(),
            request_digest: request.request_digest().clone(),
            response_digest: None,
            response_bytes: None,
            credential_revision: request.credential_revision(),
            provenance: self.provenance,
        });
    }

    fn add_paper(&mut self, paper: PaperMetadata) -> Result<(), ServiceError> {
        if !self.scope.allows_paper(&paper.paper_id) || !self.scope.allows_venue(paper.venue_id()) {
            return Err(ServiceError::ScopeMismatch);
        }
        for author in &paper.authors {
            if !self.scope.allows_author(&author.author_id) {
                return Err(ServiceError::ScopeMismatch);
            }
        }
        if !self.seen_records.insert(paper.digest.clone()) {
            return Err(ServiceError::DuplicateRecord);
        }
        self.papers.push(paper);
        Ok(())
    }

    fn add_citation(
        &mut self,
        citation: CitationRecord,
        to_references: bool,
    ) -> Result<(), ServiceError> {
        let expected_direction = if to_references {
            crate::CitationDirection::CitedBy
        } else {
            crate::CitationDirection::Citing
        };
        if citation.direction != expected_direction {
            return Err(ServiceError::Provider(ProviderError::ResponseTampered));
        }
        if !self.scope.allows_paper(&citation.paper.paper_id)
            || !self.scope.allows_venue(citation.paper.venue_id())
        {
            return Err(ServiceError::ScopeMismatch);
        }
        for author in &citation.paper.authors {
            if !self.scope.allows_author(&author.author_id) {
                return Err(ServiceError::ScopeMismatch);
            }
        }
        if !self.seen_records.insert(citation.edge_digest.clone()) {
            return Err(ServiceError::DuplicateRecord);
        }
        let current_count = self.citations.len() + self.references.len();
        if current_count >= crate::MAX_CITATIONS_OR_REFERENCES {
            return Err(ServiceError::ResultBoundExceeded);
        }
        if to_references {
            self.references.push(citation);
        } else {
            self.citations.push(citation);
        }
        Ok(())
    }

    fn next_cursor(&self) -> Option<&OpaqueCursor> {
        self.next_cursor.as_ref()
    }

    fn record_count(&self) -> usize {
        self.papers.len()
            + self.authors.len()
            + self.citations.len()
            + self.references.len()
            + self.recommendations.len()
    }

    fn finish(
        self,
        forced_status: Option<ResearchResultStatus>,
    ) -> Result<SemanticScholarResearchResultEvidence, ServiceError> {
        let response_digest = Digest::from_serializable(&self.response_digests)?;
        let status = forced_status.unwrap_or_else(|| {
            if self.record_count() == 0 {
                ResearchResultStatus::Empty
            } else if self.partial {
                ResearchResultStatus::Partial
            } else if self.papers.iter().any(|paper| {
                matches!(
                    paper.retraction_state,
                    crate::RetractionState::Retracted | crate::RetractionState::Unknown
                )
            }) {
                ResearchResultStatus::RetractedOrUnknown
            } else if !self.papers.is_empty()
                && self
                    .papers
                    .iter()
                    .all(|paper| !paper.abstract_state.is_available())
            {
                ResearchResultStatus::NoAbstract
            } else {
                ResearchResultStatus::Indexed
            }
        });
        let mut redactions = vec![
            crate::RedactionNotice::AbstractText,
            crate::RedactionNotice::FullText,
            crate::RedactionNotice::PdfUrl,
            crate::RedactionNotice::PaperUrl,
            crate::RedactionNotice::AuthorContactData,
            crate::RedactionNotice::AuthorAffiliation,
            crate::RedactionNotice::AuthorHomepage,
            crate::RedactionNotice::RawGraphBody,
        ];
        if !self.citations.is_empty() || !self.references.is_empty() {
            redactions.push(crate::RedactionNotice::CitationContext);
            redactions.push(crate::RedactionNotice::CitationIntent);
        }
        redactions.push(crate::RedactionNotice::RankingOrQualityClaim);
        let mut evidence = SemanticScholarResearchResultEvidence {
            status,
            provenance: self.provenance,
            query_digest: self.registration.query_digest.clone(),
            query_revision: self.registration.query_revision,
            scope_digest: self.registration.scope_digest.clone(),
            permission_digest: self.registration.permission_digest.clone(),
            consent_digest: self.registration.consent_digest.clone(),
            registration_digest: self.registration.registration_digest.clone(),
            provider_digest: self.registration.provider_digest.clone(),
            request_receipts: self.request_receipts,
            response_digests: self.response_digests,
            response_digest,
            papers: self.papers,
            authors: self.authors,
            citations: self.citations,
            references: self.references,
            recommendations: self.recommendations,
            retry: self.retry,
            provider_error: self.provider_error,
            redactions,
            result_digest: Digest::from_text("result-placeholder"),
        };
        evidence.result_digest = evidence.compute_digest()?;
        Ok(evidence)
    }
}

// Keep the public service module's imports honest and make the transport
// provenance boundary explicit in rustdoc.
#[allow(dead_code)]
fn _scope_types(
    _host: ApiHost,
    _version: ApiVersion,
    _consent: ConsentDataClass,
    _native: NativeTransportProvenance,
    _definition: SemanticScholarProviderDefinition,
    _request: Option<ApiGetRequest>,
    _id: Option<crate::PaperId>,
) {
}
