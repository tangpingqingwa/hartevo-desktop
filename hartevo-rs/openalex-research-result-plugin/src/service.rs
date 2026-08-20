use std::fmt;

use thiserror::Error;

use crate::{
    Digest, MAX_RESPONSE_BYTES, MAX_RESULTS, MISSION_OPENALEX_RESEARCH_CONSUMER_ID, ModelError,
    OPENALEX_RESEARCH_RESULT_CONTRACT_VERSION, OPENALEX_RESEARCH_RESULT_SCHEMA_VERSION,
    OpenAlexEvidenceState, OpenAlexObservationReceipt, OpenAlexPermission, OpenAlexProvider,
    OpenAlexProviderError, OpenAlexProviderRead, OpenAlexReadReceipt, OpenAlexRegistration,
    OpenAlexResearchEvidence, OpenAlexResearchProposal, OpenAlexResearchScope, OpenAlexTransport,
    OpenAlexWorkProjection, RateLimitReceipt, RecommendationDisposition, RegistrationState,
    RegistrationTransitionReceipt, TransportProvenance, canonical_digest, sha256_digest,
};

pub const OPENALEX_RESEARCH_RESULT_SERVICE_ID: &str = "openalex.research-result";

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum OpenAlexResearchResultServiceError {
    #[error("OpenAlex registration is revoked")]
    RegistrationRevoked,
    #[error("OpenAlex registration is stale, tampered, or drifted")]
    RegistrationDrift,
    #[error("OpenAlex SecretReference is revoked")]
    SecretRevoked,
    #[error("OpenAlex metadata.read permission is missing")]
    MissingMetadataPermission,
    #[error("OpenAlex scope is stale or does not match the service")]
    ScopeMismatch,
    #[error("OpenAlex read consent is denied or stale")]
    ConsentMismatch,
    #[error("OpenAlex cursor is not bound to the query and revision")]
    CursorBindingMismatch,
    #[error("OpenAlex evidence digest or binding verification failed")]
    EvidenceMismatch,
    #[error("OpenAlex proposal digest or binding verification failed")]
    ProposalMismatch,
    #[error("OpenAlex proposal replay or stale registration was rejected")]
    ReplayDetected,
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenAlexResearchResultServiceDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub contract_digest: Digest,
    pub read_only: bool,
    pub live_execution: bool,
    pub emits_outcome: bool,
    pub external_writes: bool,
    pub connected: bool,
    pub native: bool,
    pub ranking_authority: bool,
    pub full_text_authority: bool,
    pub research_truth_authority: bool,
}

impl Default for OpenAlexResearchResultServiceDefinition {
    fn default() -> Self {
        Self {
            schema_version: OPENALEX_RESEARCH_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: OPENALEX_RESEARCH_RESULT_CONTRACT_VERSION.to_owned(),
            service_id: OPENALEX_RESEARCH_RESULT_SERVICE_ID.to_owned(),
            provider_id: crate::OPENALEX_PROVIDER_ID.to_owned(),
            consumer_id: MISSION_OPENALEX_RESEARCH_CONSUMER_ID.to_owned(),
            contract_digest: crate::contract_digest(),
            read_only: true,
            live_execution: false,
            emits_outcome: false,
            external_writes: false,
            connected: false,
            native: false,
            ranking_authority: false,
            full_text_authority: false,
            research_truth_authority: false,
        }
    }
}

/// Typed Layer-1 service for bounded OpenAlex evidence. It prepares proposals
/// and observation receipts but never creates a kernel receipt, claims
/// research Truth, ranks works, reads full text, or adopts a Work Product or
/// Outcome.
pub struct OpenAlexResearchResultService<T: OpenAlexTransport> {
    provider: OpenAlexProvider<T>,
    definition: OpenAlexResearchResultServiceDefinition,
}

impl<T: OpenAlexTransport> fmt::Debug for OpenAlexResearchResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenAlexResearchResultService")
            .field("provider", &self.provider)
            .field("definition", &self.definition)
            .finish()
    }
}

impl<T: OpenAlexTransport> OpenAlexResearchResultService<T> {
    pub fn new(provider: OpenAlexProvider<T>) -> Result<Self, OpenAlexResearchResultServiceError> {
        provider
            .registration()
            .validate(
                provider.scope(),
                provider.permission(),
                provider.secret_reference(),
                &provider.provider_digest(),
            )
            .map_err(map_registration_error)?;
        Ok(Self {
            provider,
            definition: OpenAlexResearchResultServiceDefinition::default(),
        })
    }

    #[must_use]
    pub fn from_provider(provider: OpenAlexProvider<T>) -> Self {
        Self {
            provider,
            definition: OpenAlexResearchResultServiceDefinition::default(),
        }
    }

    #[must_use]
    pub fn provider(&self) -> &OpenAlexProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut OpenAlexProvider<T> {
        &mut self.provider
    }

    #[must_use]
    pub fn scope(&self) -> &OpenAlexResearchScope {
        self.provider.scope()
    }

    #[must_use]
    pub fn permission(&self) -> &OpenAlexPermission {
        self.provider.permission()
    }

    #[must_use]
    pub fn registration(&self) -> &OpenAlexRegistration {
        self.provider.registration()
    }

    #[must_use]
    pub fn service_definition(&self) -> &OpenAlexResearchResultServiceDefinition {
        &self.definition
    }

    #[must_use]
    pub fn issue_read_consent(&self) -> crate::ConsentScope {
        self.scope().consent().clone()
    }

    pub fn read(&mut self) -> Result<OpenAlexResearchEvidence, OpenAlexResearchResultServiceError> {
        let consent = self.issue_read_consent();
        self.read_with_consent(&consent)
    }

    pub fn read_with_consent(
        &mut self,
        consent: &crate::ConsentScope,
    ) -> Result<OpenAlexResearchEvidence, OpenAlexResearchResultServiceError> {
        self.validate_consent(consent)?;
        match self.provider.read() {
            Ok(read) => Ok(self.evidence_from_read(read)),
            Err(OpenAlexProviderError::RegistrationRevoked) => {
                Err(OpenAlexResearchResultServiceError::RegistrationRevoked)
            }
            Err(
                OpenAlexProviderError::RegistrationDrift
                | OpenAlexProviderError::ProviderDefinitionDrift
                | OpenAlexProviderError::RequestNotAllowlisted,
            ) => Err(OpenAlexResearchResultServiceError::RegistrationDrift),
            Err(OpenAlexProviderError::SecretRevoked) => {
                Err(OpenAlexResearchResultServiceError::SecretRevoked)
            }
            Err(OpenAlexProviderError::MissingMetadataPermission) => {
                Err(OpenAlexResearchResultServiceError::MissingMetadataPermission)
            }
            Err(OpenAlexProviderError::ScopeMismatch) => {
                Err(OpenAlexResearchResultServiceError::ScopeMismatch)
            }
            Err(OpenAlexProviderError::CursorBindingMismatch) => {
                Err(OpenAlexResearchResultServiceError::CursorBindingMismatch)
            }
            Err(error) => Ok(self.failure_evidence(error)),
        }
    }

    pub fn compile_proposal(
        &mut self,
    ) -> Result<OpenAlexResearchProposal, OpenAlexResearchResultServiceError> {
        let evidence = self.read()?;
        self.compile_proposal_from_evidence(evidence)
    }

    pub fn compile_research_proposal(
        &mut self,
    ) -> Result<OpenAlexResearchProposal, OpenAlexResearchResultServiceError> {
        self.compile_proposal()
    }

    pub fn compile_proposal_with_consent(
        &mut self,
        consent: &crate::ConsentScope,
    ) -> Result<OpenAlexResearchProposal, OpenAlexResearchResultServiceError> {
        let evidence = self.read_with_consent(consent)?;
        self.compile_proposal_from_evidence(evidence)
    }

    pub fn compile_proposal_from_evidence(
        &self,
        evidence: OpenAlexResearchEvidence,
    ) -> Result<OpenAlexResearchProposal, OpenAlexResearchResultServiceError> {
        self.ensure_registration()?;
        self.verify_evidence(&evidence)?;
        let mut proposal = OpenAlexResearchProposal {
            scope: self.scope().clone(),
            source_evidence_digest: evidence.digest(),
            idempotency_digest: evidence.idempotency_digest.clone(),
            evidence,
            registration_digest: self.registration().registration_digest.clone(),
            provider_digest: self.provider.provider_digest(),
            permission_digest: self.permission().digest(),
            contract_digest: crate::contract_digest(),
            proposal_only: true,
            native: false,
            connected: false,
            adopts_outcome: false,
            adopts_work_product: false,
            ranking_claim: false,
            full_text: false,
            author_identity_claim: false,
            citation_truth_claim: false,
            research_truth_claim: false,
            recommendation: RecommendationDisposition::ReviewProviderMetadata,
            proposal_digest: String::new(),
        };
        proposal.recommendation = recommendation_for(&proposal.evidence);
        proposal.proposal_digest = proposal.digest();
        Ok(proposal)
    }

    pub fn verify_evidence(
        &self,
        evidence: &OpenAlexResearchEvidence,
    ) -> Result<(), OpenAlexResearchResultServiceError> {
        self.ensure_registration()?;
        let expected_cursor_digest = self
            .scope()
            .cursor()
            .map(|cursor| cursor.cursor_digest().to_owned());
        if evidence.evidence_digest != evidence.digest()
            || evidence.entity != self.scope().query().entity()
            || evidence.operation != self.scope().query().operation()
            || evidence.query_digest != self.scope().query().digest()
            || evidence.filter_digest != self.scope().query().filter_digest()
            || evidence.scope_digest != self.scope().digest()
            || evidence.consent_digest != self.scope().consent().digest()
            || evidence.provider_digest != self.provider.provider_digest()
            || evidence.registration_digest != self.registration().registration_digest
            || evidence.response_digest != evidence.read_receipt.response_digest
            || evidence.idempotency_digest != evidence.read_receipt.idempotency_digest
            || evidence.cursor_digest != expected_cursor_digest
            || crate::model::validate_digest(&evidence.response_digest).is_err()
            || crate::model::validate_digest(&evidence.idempotency_digest).is_err()
            || crate::model::validate_digest(&evidence.read_receipt.request_digest).is_err()
            || evidence.rate_limit.validate().is_err()
            || evidence.read_receipt.rate_limit_digest != evidence.rate_limit.digest()
            || evidence.read_receipt.connected
            || evidence.read_receipt.native
            || evidence.read_receipt.provenance != self.provider.transport_provenance()
            || evidence.read_receipt.provenance.connected()
            || evidence.read_receipt.provenance.native()
            || !matches!(
                evidence.read_receipt.provenance,
                TransportProvenance::Fixture
                    | TransportProvenance::Recording
                    | TransportProvenance::Loopback
                    | TransportProvenance::BlockedEnv
            )
        {
            return Err(OpenAlexResearchResultServiceError::EvidenceMismatch);
        }
        if let Some(cursor) = &evidence.next_cursor
            && (cursor.validate().is_err()
                || cursor.query_digest() != self.scope().query().digest()
                || cursor.scope_revision() != self.scope().revision())
        {
            return Err(OpenAlexResearchResultServiceError::EvidenceMismatch);
        }
        if evidence.returned_results > self.scope().page_size()
            || evidence.works.len() > MAX_RESULTS
            || evidence.authors.len() > MAX_RESULTS
            || evidence.institutions.len() > MAX_RESULTS
            || evidence.concepts.len() > MAX_RESULTS
            || evidence.citations.len() > MAX_RESULTS
        {
            return Err(OpenAlexResearchResultServiceError::EvidenceMismatch);
        }
        let expected_returned = if evidence.operation.is_citation() {
            evidence.citations.len()
        } else {
            match evidence.entity {
                crate::OpenAlexEntity::Work => evidence.works.len(),
                crate::OpenAlexEntity::Author => evidence.authors.len(),
                crate::OpenAlexEntity::Institution => evidence.institutions.len(),
                crate::OpenAlexEntity::Concept => evidence.concepts.len(),
            }
        };
        if evidence.returned_results != expected_returned {
            return Err(OpenAlexResearchResultServiceError::EvidenceMismatch);
        }
        if evidence
            .total_results
            .is_some_and(|total| total < expected_returned as u64)
        {
            return Err(OpenAlexResearchResultServiceError::EvidenceMismatch);
        }
        let only_expected_entity = match evidence.entity {
            crate::OpenAlexEntity::Work => {
                evidence.authors.is_empty()
                    && evidence.institutions.is_empty()
                    && evidence.concepts.is_empty()
            }
            crate::OpenAlexEntity::Author => {
                evidence.works.is_empty()
                    && evidence.institutions.is_empty()
                    && evidence.concepts.is_empty()
                    && evidence.citations.is_empty()
            }
            crate::OpenAlexEntity::Institution => {
                evidence.works.is_empty()
                    && evidence.authors.is_empty()
                    && evidence.concepts.is_empty()
                    && evidence.citations.is_empty()
            }
            crate::OpenAlexEntity::Concept => {
                evidence.works.is_empty()
                    && evidence.authors.is_empty()
                    && evidence.institutions.is_empty()
                    && evidence.citations.is_empty()
            }
        };
        if !only_expected_entity
            || (!evidence.operation.is_citation() && !evidence.citations.is_empty())
        {
            return Err(OpenAlexResearchResultServiceError::EvidenceMismatch);
        }
        for work in &evidence.works {
            work.validate()
                .map_err(|_| OpenAlexResearchResultServiceError::EvidenceMismatch)?;
        }
        for author in &evidence.authors {
            author
                .validate()
                .map_err(|_| OpenAlexResearchResultServiceError::EvidenceMismatch)?;
        }
        for institution in &evidence.institutions {
            institution
                .validate()
                .map_err(|_| OpenAlexResearchResultServiceError::EvidenceMismatch)?;
        }
        for concept in &evidence.concepts {
            concept
                .validate()
                .map_err(|_| OpenAlexResearchResultServiceError::EvidenceMismatch)?;
        }
        for citation in &evidence.citations {
            citation
                .validate()
                .map_err(|_| OpenAlexResearchResultServiceError::EvidenceMismatch)?;
        }
        Ok(())
    }

    pub fn verify_proposal(
        &self,
        proposal: &OpenAlexResearchProposal,
    ) -> Result<(), OpenAlexResearchResultServiceError> {
        self.ensure_registration()?;
        self.verify_evidence(&proposal.evidence)?;
        if proposal.proposal_digest != proposal.digest()
            || proposal.source_evidence_digest != proposal.evidence.digest()
            || proposal.idempotency_digest != proposal.evidence.idempotency_digest
            || proposal.scope.digest() != self.scope().digest()
            || proposal.registration_digest != self.registration().registration_digest
            || proposal.provider_digest != self.provider.provider_digest()
            || proposal.permission_digest != self.permission().digest()
            || proposal.contract_digest != crate::contract_digest()
            || !proposal.proposal_only
            || proposal.native
            || proposal.connected
            || proposal.adopts_outcome
            || proposal.adopts_work_product
            || proposal.ranking_claim
            || proposal.full_text
            || proposal.author_identity_claim
            || proposal.citation_truth_claim
            || proposal.research_truth_claim
        {
            return Err(OpenAlexResearchResultServiceError::ProposalMismatch);
        }
        Ok(())
    }

    pub fn record_receipt(
        &self,
        proposal: &OpenAlexResearchProposal,
    ) -> Result<OpenAlexObservationReceipt, OpenAlexResearchResultServiceError> {
        self.verify_proposal(proposal)?;
        let mut receipt = OpenAlexObservationReceipt {
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.source_evidence_digest.clone(),
            idempotency_digest: proposal.idempotency_digest.clone(),
            registration_digest: self.registration().registration_digest.clone(),
            provider_digest: self.provider.provider_digest(),
            response_digest: proposal.evidence.response_digest.clone(),
            state: proposal.evidence.state,
            provenance: proposal.evidence.read_receipt.provenance,
            connected: false,
            native: false,
            durable_native_receipt: false,
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = receipt.digest();
        Ok(receipt)
    }

    pub fn record_observation_receipt(
        &self,
        proposal: &OpenAlexResearchProposal,
    ) -> Result<OpenAlexObservationReceipt, OpenAlexResearchResultServiceError> {
        self.record_receipt(proposal)
    }

    pub fn revoke_registration(
        &mut self,
    ) -> Result<RegistrationTransitionReceipt, OpenAlexResearchResultServiceError> {
        let from = self.registration().state;
        self.provider
            .registration_mut()
            .revoke()
            .map_err(map_transition_error)?;
        Ok(transition_receipt(
            from,
            self.registration().state,
            self.registration(),
        ))
    }

    pub fn restore_registration(
        &mut self,
    ) -> Result<RegistrationTransitionReceipt, OpenAlexResearchResultServiceError> {
        let from = self.registration().state;
        self.provider
            .registration_mut()
            .restore()
            .map_err(map_transition_error)?;
        Ok(transition_receipt(
            from,
            self.registration().state,
            self.registration(),
        ))
    }

    fn validate_consent(
        &self,
        consent: &crate::ConsentScope,
    ) -> Result<(), OpenAlexResearchResultServiceError> {
        consent
            .validate()
            .map_err(|_| OpenAlexResearchResultServiceError::ConsentMismatch)?;
        if consent.digest() != self.scope().consent().digest() {
            return Err(OpenAlexResearchResultServiceError::ConsentMismatch);
        }
        Ok(())
    }

    fn ensure_registration(&self) -> Result<(), OpenAlexResearchResultServiceError> {
        if !self.registration().state.is_active() {
            return Err(OpenAlexResearchResultServiceError::RegistrationRevoked);
        }
        if self.provider.secret_reference().is_revoked() {
            return Err(OpenAlexResearchResultServiceError::SecretRevoked);
        }
        self.registration()
            .validate(
                self.scope(),
                self.permission(),
                self.provider.secret_reference(),
                &self.provider.provider_digest(),
            )
            .map_err(map_registration_error)
    }

    fn evidence_from_read(&self, read: OpenAlexProviderRead) -> OpenAlexResearchEvidence {
        let state = if read.rate_limit.throttled || read.status == 429 {
            OpenAlexEvidenceState::RateLimited
        } else if read.status == 401 || read.status == 403 {
            OpenAlexEvidenceState::AccessLost
        } else if read.status == 404 {
            OpenAlexEvidenceState::Empty
        } else if !(200..300).contains(&read.status) {
            OpenAlexEvidenceState::ProviderUnknown
        } else if read_entity_count(&read) == 0 && read.total_results == Some(0) {
            OpenAlexEvidenceState::Empty
        } else if read.partial {
            OpenAlexEvidenceState::Partial
        } else {
            OpenAlexEvidenceState::Complete
        };
        let reason = match state {
            OpenAlexEvidenceState::Partial => Some("bounded_or_invalid_items".to_owned()),
            OpenAlexEvidenceState::RateLimited => Some("provider_rate_limit".to_owned()),
            OpenAlexEvidenceState::AccessLost => Some("provider_access_denied".to_owned()),
            OpenAlexEvidenceState::Empty => Some("no_metadata_items".to_owned()),
            _ => None,
        };
        self.build_evidence(read, state, reason)
    }

    fn failure_evidence(&self, error: OpenAlexProviderError) -> OpenAlexResearchEvidence {
        let provenance = self.provider.transport_provenance();
        let (state, status, response_digest, response_bytes, rate_limit, reason, provenance) =
            match error {
                OpenAlexProviderError::BlockedEnv => (
                    OpenAlexEvidenceState::BlockedEnv,
                    0,
                    sha256_digest(b"BLOCKED_ENV"),
                    0,
                    RateLimitReceipt::default(),
                    Some("BLOCKED_ENV".to_owned()),
                    TransportProvenance::BlockedEnv,
                ),
                OpenAlexProviderError::Timeout => (
                    OpenAlexEvidenceState::ProviderUnknown,
                    0,
                    sha256_digest(b"TIMEOUT"),
                    0,
                    RateLimitReceipt::default(),
                    Some("transport_timeout".to_owned()),
                    provenance,
                ),
                OpenAlexProviderError::ProviderUnknown => (
                    OpenAlexEvidenceState::ProviderUnknown,
                    0,
                    sha256_digest(b"PROVIDER_UNKNOWN"),
                    0,
                    RateLimitReceipt::default(),
                    Some("provider_unknown".to_owned()),
                    provenance,
                ),
                OpenAlexProviderError::ResponseTooLarge {
                    status,
                    response_digest,
                    response_bytes,
                    rate_limit,
                    provenance,
                } => (
                    OpenAlexEvidenceState::ResponseTooLarge,
                    status,
                    response_digest,
                    response_bytes,
                    rate_limit,
                    Some("response_too_large".to_owned()),
                    provenance,
                ),
                OpenAlexProviderError::MalformedResponse {
                    status,
                    response_digest,
                    response_bytes,
                    rate_limit,
                    provenance,
                    ..
                } => (
                    OpenAlexEvidenceState::MalformedResponse,
                    status,
                    response_digest,
                    response_bytes,
                    rate_limit,
                    Some("malformed_response".to_owned()),
                    provenance,
                ),
                _ => (
                    OpenAlexEvidenceState::ProviderUnknown,
                    0,
                    sha256_digest(b"PROVIDER_ERROR"),
                    0,
                    RateLimitReceipt::default(),
                    Some("provider_error".to_owned()),
                    provenance,
                ),
            };
        let read = OpenAlexProviderRead {
            status,
            response_digest,
            response_bytes,
            request_digest: sha256_digest(b"NO_REQUEST"),
            idempotency_digest: self.failure_idempotency_digest(),
            rate_limit,
            provenance,
            entity: self.scope().query().entity(),
            operation: self.scope().query().operation(),
            query_digest: self.scope().query().digest(),
            selector_digest: self.scope().query().selector_digest().to_owned(),
            filter_digest: self.scope().query().filter_digest().to_owned(),
            scope_revision: self.scope().revision().get(),
            cursor_digest: self
                .scope()
                .cursor()
                .map(|cursor| cursor.cursor_digest().to_owned()),
            next_cursor: None,
            total_results: None,
            works: Vec::new(),
            authors: Vec::new(),
            institutions: Vec::new(),
            concepts: Vec::new(),
            citations: Vec::new(),
            partial: false,
        };
        self.build_evidence(read, state, reason)
    }

    #[allow(clippy::too_many_arguments)]
    fn build_evidence(
        &self,
        read: OpenAlexProviderRead,
        state: OpenAlexEvidenceState,
        partial_reason: Option<String>,
    ) -> OpenAlexResearchEvidence {
        let returned_results = read_entity_count(&read);
        let read_receipt = OpenAlexReadReceipt {
            status: read.status,
            response_digest: read.response_digest.clone(),
            response_bytes: read.response_bytes.min(MAX_RESPONSE_BYTES),
            request_digest: read.request_digest,
            idempotency_digest: read.idempotency_digest.clone(),
            rate_limit_digest: read.rate_limit.digest(),
            provenance: read.provenance,
            connected: false,
            native: false,
        };
        let mut evidence = OpenAlexResearchEvidence {
            entity: read.entity,
            operation: read.operation,
            query_digest: read.query_digest,
            filter_digest: read.filter_digest,
            scope_digest: self.scope().digest(),
            consent_digest: self.scope().consent().digest(),
            provider_digest: self.provider.provider_digest(),
            registration_digest: self.registration().registration_digest.clone(),
            response_digest: read_receipt.response_digest.clone(),
            idempotency_digest: read_receipt.idempotency_digest.clone(),
            cursor_digest: read.cursor_digest,
            next_cursor: read.next_cursor,
            state,
            total_results: read.total_results,
            returned_results,
            works: read.works,
            authors: read.authors,
            institutions: read.institutions,
            concepts: read.concepts,
            citations: read.citations,
            partial_reason,
            rate_limit: read.rate_limit,
            read_receipt,
            evidence_digest: String::new(),
        };
        evidence.evidence_digest = evidence.digest();
        evidence
    }

    fn failure_idempotency_digest(&self) -> Digest {
        canonical_digest(&(
            self.scope().digest(),
            self.registration().registration_digest.clone(),
            "failure",
        ))
    }
}

fn read_entity_count(read: &OpenAlexProviderRead) -> usize {
    if read.operation.is_citation() {
        read.citations.len()
    } else {
        match read.entity {
            crate::OpenAlexEntity::Work => read.works.len(),
            crate::OpenAlexEntity::Author => read.authors.len(),
            crate::OpenAlexEntity::Institution => read.institutions.len(),
            crate::OpenAlexEntity::Concept => read.concepts.len(),
        }
    }
}

fn recommendation_for(evidence: &OpenAlexResearchEvidence) -> RecommendationDisposition {
    match evidence.state {
        OpenAlexEvidenceState::Complete => RecommendationDisposition::ReviewProviderMetadata,
        OpenAlexEvidenceState::Partial => RecommendationDisposition::ReviewPartialMetadata,
        OpenAlexEvidenceState::Empty => RecommendationDisposition::NoMetadata,
        OpenAlexEvidenceState::RateLimited => RecommendationDisposition::RetryAfterRateLimit,
        OpenAlexEvidenceState::AccessLost
        | OpenAlexEvidenceState::ProviderUnknown
        | OpenAlexEvidenceState::BlockedEnv
        | OpenAlexEvidenceState::MalformedResponse
        | OpenAlexEvidenceState::ResponseTooLarge => RecommendationDisposition::ProviderUnavailable,
    }
}

fn map_registration_error(error: ModelError) -> OpenAlexResearchResultServiceError {
    match error {
        ModelError::AlreadyRevoked => OpenAlexResearchResultServiceError::RegistrationRevoked,
        ModelError::InvalidScope("secret reference revoked") => {
            OpenAlexResearchResultServiceError::SecretRevoked
        }
        _ => OpenAlexResearchResultServiceError::RegistrationDrift,
    }
}

fn map_transition_error(error: ModelError) -> OpenAlexResearchResultServiceError {
    match error {
        ModelError::AlreadyRevoked => OpenAlexResearchResultServiceError::RegistrationRevoked,
        ModelError::NotRevoked => OpenAlexResearchResultServiceError::RegistrationDrift,
        other => OpenAlexResearchResultServiceError::Model(other),
    }
}

fn transition_receipt(
    from: RegistrationState,
    to: RegistrationState,
    registration: &OpenAlexRegistration,
) -> RegistrationTransitionReceipt {
    let mut receipt = RegistrationTransitionReceipt {
        from,
        to,
        registration_digest: registration.registration_digest.clone(),
        revision: registration.revision,
        reversible: true,
        transition_digest: String::new(),
    };
    receipt.transition_digest = receipt.digest();
    receipt
}

#[allow(dead_code)]
fn _work_digest_for_clippy(work: &OpenAlexWorkProjection) -> Digest {
    work.digest()
}
