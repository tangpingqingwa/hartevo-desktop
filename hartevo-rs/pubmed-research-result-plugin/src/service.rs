use std::fmt;

use thiserror::Error;

use crate::{
    Digest, MAX_RESPONSE_BYTES, MISSION_PUBMED_RESEARCH_CONSUMER_ID, ModelError,
    NcbiEutilsProvider, NcbiEutilsProviderError, NcbiEutilsProviderRead, NcbiEutilsTransport,
    PUBMED_RESEARCH_RESULT_CONTRACT_VERSION, PUBMED_RESEARCH_RESULT_SCHEMA_VERSION,
    PubMedEvidenceState, PubMedObservationReceipt, PubMedPermission, PubMedReadReceipt,
    PubMedRegistration, PubMedRequest, PubMedResearchEvidence, PubMedResearchProposal,
    PubMedResearchScope, RecommendationDisposition, RegistrationState,
    RegistrationTransitionReceipt, TransportProvenance, canonical_digest, sha256_digest,
};

pub const PUBMED_RESEARCH_RESULT_SERVICE_ID: &str = "pubmed.research-result";

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum PubMedResearchResultServiceError {
    #[error("PubMed registration is revoked")]
    RegistrationRevoked,
    #[error("PubMed registration is stale, tampered, or drifted")]
    RegistrationDrift,
    #[error("PubMed SecretReference is revoked")]
    SecretRevoked,
    #[error("PubMed metadata.read permission is missing")]
    MissingMetadataPermission,
    #[error("PubMed scope is stale or does not match the service")]
    ScopeMismatch,
    #[error("PubMed read consent is denied or stale")]
    ConsentMismatch,
    #[error("PubMed cursor is stale or bound to another query")]
    CursorMismatch,
    #[error("PubMed history binding is stale or bound to another query")]
    HistoryMismatch,
    #[error("PubMed cursor replay or idempotency replay was rejected")]
    ReplayDetected,
    #[error("PubMed evidence digest or binding verification failed")]
    EvidenceMismatch,
    #[error("PubMed proposal digest or binding verification failed")]
    ProposalMismatch,
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PubMedResearchResultServiceDefinition {
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
    pub first_party: bool,
}

impl Default for PubMedResearchResultServiceDefinition {
    fn default() -> Self {
        Self {
            schema_version: PUBMED_RESEARCH_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: PUBMED_RESEARCH_RESULT_CONTRACT_VERSION.to_owned(),
            service_id: PUBMED_RESEARCH_RESULT_SERVICE_ID.to_owned(),
            provider_id: crate::NCBI_EUTILS_PROVIDER_ID.to_owned(),
            consumer_id: MISSION_PUBMED_RESEARCH_CONSUMER_ID.to_owned(),
            contract_digest: crate::contract_digest(),
            read_only: true,
            live_execution: false,
            emits_outcome: false,
            external_writes: false,
            connected: false,
            native: false,
            first_party: false,
        }
    }
}

/// Typed Layer-1 service for bounded PubMed publication metadata evidence.
/// It prepares proposals and observation receipts but never creates a kernel
/// receipt, claims clinical or citation truth, or adopts a Work Product.
pub struct PubMedResearchResultService<T: NcbiEutilsTransport> {
    provider: NcbiEutilsProvider<T>,
    definition: PubMedResearchResultServiceDefinition,
}

impl<T: NcbiEutilsTransport> fmt::Debug for PubMedResearchResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PubMedResearchResultService")
            .field("provider", &self.provider)
            .field("definition", &self.definition)
            .finish()
    }
}

impl<T: NcbiEutilsTransport> PubMedResearchResultService<T> {
    pub fn new(provider: NcbiEutilsProvider<T>) -> Result<Self, PubMedResearchResultServiceError> {
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
            definition: PubMedResearchResultServiceDefinition::default(),
        })
    }

    #[must_use]
    pub fn from_provider(provider: NcbiEutilsProvider<T>) -> Self {
        Self {
            provider,
            definition: PubMedResearchResultServiceDefinition::default(),
        }
    }

    #[must_use]
    pub fn provider(&self) -> &NcbiEutilsProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut NcbiEutilsProvider<T> {
        &mut self.provider
    }

    #[must_use]
    pub fn scope(&self) -> &PubMedResearchScope {
        self.provider.scope()
    }

    #[must_use]
    pub fn permission(&self) -> &PubMedPermission {
        self.provider.permission()
    }

    #[must_use]
    pub fn registration(&self) -> &PubMedRegistration {
        self.provider.registration()
    }

    #[must_use]
    pub fn service_definition(&self) -> &PubMedResearchResultServiceDefinition {
        &self.definition
    }

    #[must_use]
    pub fn issue_read_consent(&self) -> crate::ConsentScope {
        self.scope().consent().clone()
    }

    pub fn build_request(&self) -> Result<PubMedRequest, PubMedResearchResultServiceError> {
        self.provider.build_request().map_err(map_provider_error)
    }

    pub fn read(&mut self) -> Result<PubMedResearchEvidence, PubMedResearchResultServiceError> {
        self.read_with_consent_and_page(&self.issue_read_consent(), None, None)
    }

    pub fn read_with_page(
        &mut self,
        cursor: Option<crate::OpaqueCursor>,
        history: Option<crate::OpaqueHistory>,
    ) -> Result<PubMedResearchEvidence, PubMedResearchResultServiceError> {
        let consent = self.issue_read_consent();
        self.read_with_consent_and_page(&consent, cursor, history)
    }

    pub fn read_page(
        &mut self,
        cursor: Option<crate::OpaqueCursor>,
        history: Option<crate::OpaqueHistory>,
    ) -> Result<PubMedResearchEvidence, PubMedResearchResultServiceError> {
        self.read_with_page(cursor, history)
    }

    pub fn read_with_consent(
        &mut self,
        consent: &crate::ConsentScope,
    ) -> Result<PubMedResearchEvidence, PubMedResearchResultServiceError> {
        self.read_with_consent_and_page(consent, None, None)
    }

    fn read_with_consent_and_page(
        &mut self,
        consent: &crate::ConsentScope,
        cursor: Option<crate::OpaqueCursor>,
        history: Option<crate::OpaqueHistory>,
    ) -> Result<PubMedResearchEvidence, PubMedResearchResultServiceError> {
        self.validate_consent(consent)?;
        match self.provider.read_with_page(cursor, history) {
            Ok(read) => Ok(self.evidence_from_read(read)),
            Err(NcbiEutilsProviderError::RegistrationRevoked) => {
                Err(PubMedResearchResultServiceError::RegistrationRevoked)
            }
            Err(
                NcbiEutilsProviderError::RegistrationDrift
                | NcbiEutilsProviderError::ProviderDefinitionDrift
                | NcbiEutilsProviderError::RequestNotAllowlisted,
            ) => Err(PubMedResearchResultServiceError::RegistrationDrift),
            Err(NcbiEutilsProviderError::SecretRevoked) => {
                Err(PubMedResearchResultServiceError::SecretRevoked)
            }
            Err(NcbiEutilsProviderError::MissingMetadataPermission) => {
                Err(PubMedResearchResultServiceError::MissingMetadataPermission)
            }
            Err(NcbiEutilsProviderError::ScopeMismatch) => {
                Err(PubMedResearchResultServiceError::ScopeMismatch)
            }
            Err(NcbiEutilsProviderError::CursorMismatch) => {
                Err(PubMedResearchResultServiceError::CursorMismatch)
            }
            Err(NcbiEutilsProviderError::HistoryMismatch) => {
                Err(PubMedResearchResultServiceError::HistoryMismatch)
            }
            Err(error) => Ok(self.failure_evidence(error)),
        }
    }

    pub fn compile_proposal(
        &mut self,
    ) -> Result<PubMedResearchProposal, PubMedResearchResultServiceError> {
        let evidence = self.read()?;
        self.compile_proposal_from_evidence(evidence)
    }

    pub fn compile_research_proposal(
        &mut self,
    ) -> Result<PubMedResearchProposal, PubMedResearchResultServiceError> {
        self.compile_proposal()
    }

    pub fn compile_proposal_with_consent(
        &mut self,
        consent: &crate::ConsentScope,
    ) -> Result<PubMedResearchProposal, PubMedResearchResultServiceError> {
        let evidence = self.read_with_consent(consent)?;
        self.compile_proposal_from_evidence(evidence)
    }

    pub fn compile_proposal_from_evidence(
        &self,
        evidence: PubMedResearchEvidence,
    ) -> Result<PubMedResearchProposal, PubMedResearchResultServiceError> {
        self.ensure_registration()?;
        self.verify_evidence(&evidence)?;
        let mut proposal = PubMedResearchProposal {
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
            first_party: false,
            adopts_outcome: false,
            adopts_work_product: false,
            recommendation: RecommendationDisposition::ReviewMetadata,
            proposal_digest: String::new(),
        };
        proposal.recommendation = recommendation_for(&proposal.evidence);
        proposal.proposal_digest = proposal.digest();
        Ok(proposal)
    }

    pub fn verify_evidence(
        &self,
        evidence: &PubMedResearchEvidence,
    ) -> Result<(), PubMedResearchResultServiceError> {
        self.ensure_registration()?;
        if evidence.evidence_digest != evidence.digest()
            || evidence.operation != self.scope().query().operation()
            || evidence.database != self.scope().database()
            || evidence.query_digest != self.scope().query().selector_digest()
            || evidence.pmid_digest.as_deref() != self.scope().query().pmid_digest()
            || evidence.pmcid_digest.as_deref() != self.scope().query().pmcid_digest()
            || evidence.mesh_digest.as_deref() != self.scope().query().mesh_digest()
            || evidence.scope_digest != self.scope().digest()
            || evidence.consent_digest != self.scope().consent().digest()
            || evidence.provider_digest != self.provider.provider_digest()
            || evidence.registration_digest != self.registration().registration_digest
            || evidence.response_digest != evidence.read_receipt.response_digest
            || evidence.rate_limit.digest() != evidence.read_receipt.rate_limit_digest
            || evidence.read_receipt.request_digest != evidence.request_digest
            || evidence.read_receipt.idempotency_digest != evidence.idempotency_digest
            || evidence.read_receipt.cursor_digest != evidence.cursor_digest
            || evidence.read_receipt.history_digest != evidence.history_digest
            || evidence.returned_results != evidence.articles.len() + evidence.links.len()
            || evidence.articles.len() > self.scope().max_results()
            || evidence.links.len() > self.scope().max_results()
            || evidence.read_receipt.connected
            || evidence.read_receipt.native
            || evidence.read_receipt.first_party
            || evidence.read_receipt.provenance.connected()
            || evidence.read_receipt.provenance.native()
            || evidence.read_receipt.provenance.first_party()
            || evidence.page_digest != page_digest_from_evidence(evidence)
        {
            return Err(PubMedResearchResultServiceError::EvidenceMismatch);
        }
        if let Some(total_results) = evidence.total_results
            && total_results < evidence.returned_results as u64
        {
            return Err(PubMedResearchResultServiceError::EvidenceMismatch);
        }
        for article in &evidence.articles {
            article
                .validate()
                .map_err(|_| PubMedResearchResultServiceError::EvidenceMismatch)?;
        }
        for link in &evidence.links {
            link.validate()
                .map_err(|_| PubMedResearchResultServiceError::EvidenceMismatch)?;
        }
        Ok(())
    }

    pub fn verify_proposal(
        &self,
        proposal: &PubMedResearchProposal,
    ) -> Result<(), PubMedResearchResultServiceError> {
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
            || proposal.first_party
            || proposal.adopts_outcome
            || proposal.adopts_work_product
        {
            return Err(PubMedResearchResultServiceError::ProposalMismatch);
        }
        Ok(())
    }

    pub fn record_receipt(
        &self,
        proposal: &PubMedResearchProposal,
    ) -> Result<PubMedObservationReceipt, PubMedResearchResultServiceError> {
        self.verify_proposal(proposal)?;
        let mut receipt = PubMedObservationReceipt {
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.source_evidence_digest.clone(),
            registration_digest: self.registration().registration_digest.clone(),
            provider_digest: self.provider.provider_digest(),
            response_digest: proposal.evidence.response_digest.clone(),
            state: proposal.evidence.state.clone(),
            provenance: proposal.evidence.read_receipt.provenance,
            request_digest: proposal.evidence.request_digest.clone(),
            idempotency_digest: proposal.evidence.idempotency_digest.clone(),
            connected: false,
            native: false,
            first_party: false,
            durable_native_receipt: false,
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = receipt.digest();
        Ok(receipt)
    }

    pub fn record_observation_receipt(
        &self,
        proposal: &PubMedResearchProposal,
    ) -> Result<PubMedObservationReceipt, PubMedResearchResultServiceError> {
        self.record_receipt(proposal)
    }

    pub fn revoke_registration(
        &mut self,
    ) -> Result<RegistrationTransitionReceipt, PubMedResearchResultServiceError> {
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
    ) -> Result<RegistrationTransitionReceipt, PubMedResearchResultServiceError> {
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
    ) -> Result<(), PubMedResearchResultServiceError> {
        consent
            .validate()
            .map_err(|_| PubMedResearchResultServiceError::ConsentMismatch)?;
        if consent.digest() != self.scope().consent().digest() {
            return Err(PubMedResearchResultServiceError::ConsentMismatch);
        }
        Ok(())
    }

    fn ensure_registration(&self) -> Result<(), PubMedResearchResultServiceError> {
        if !self.registration().state.is_active() {
            return Err(PubMedResearchResultServiceError::RegistrationRevoked);
        }
        if self.provider.secret_reference().is_revoked() {
            return Err(PubMedResearchResultServiceError::SecretRevoked);
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

    fn evidence_from_read(&self, read: NcbiEutilsProviderRead) -> PubMedResearchEvidence {
        let state = if read.rate_limit.throttled || read.status == 429 {
            PubMedEvidenceState::RateLimited
        } else if read.status == 401 || read.status == 403 {
            PubMedEvidenceState::Denied
        } else if read.status == 404
            || (read.articles.is_empty() && read.links.is_empty() && read.total_results == Some(0))
        {
            PubMedEvidenceState::Empty
        } else if !(200..300).contains(&read.status) {
            PubMedEvidenceState::ProviderUnknown
        } else if read.partial {
            PubMedEvidenceState::Partial
        } else {
            PubMedEvidenceState::Complete
        };
        let reason = match state {
            PubMedEvidenceState::Partial => Some("bounded_or_invalid_items".to_owned()),
            PubMedEvidenceState::RateLimited => Some("provider_rate_limit".to_owned()),
            PubMedEvidenceState::Denied => Some("provider_access_denied".to_owned()),
            PubMedEvidenceState::Empty => Some("no_bounded_records".to_owned()),
            _ => None,
        };
        self.build_evidence(
            state,
            read.status,
            read.response_digest,
            read.response_bytes,
            read.rate_limit,
            read.provenance,
            read.operation,
            read.database,
            read.query_digest,
            read.pmid_digest,
            read.pmcid_digest,
            read.mesh_digest,
            read.total_results,
            read.articles,
            read.links,
            read.next_cursor.map(|cursor| cursor.digest()),
            read.history.map(|history| history.digest()),
            read.page_digest,
            read.request_digest,
            read.idempotency_digest,
            reason,
        )
    }

    #[allow(clippy::too_many_lines)]
    fn failure_evidence(&self, error: NcbiEutilsProviderError) -> PubMedResearchEvidence {
        let provenance = self.provider.transport_provenance();
        let request = self.provider.build_request().ok();
        let request_digest = request.as_ref().map_or_else(
            || sha256_digest(b"NO_REQUEST"),
            |value| value.request_digest.clone(),
        );
        let idempotency_digest = request.as_ref().map_or_else(
            || sha256_digest(b"NO_IDEMPOTENCY"),
            |value| value.idempotency_digest.clone(),
        );
        let (state, status, response_digest, response_bytes, rate_limit, reason, provenance) =
            match error {
                NcbiEutilsProviderError::BlockedEnv => (
                    PubMedEvidenceState::BlockedEnv,
                    0,
                    sha256_digest(b"BLOCKED_ENV"),
                    0,
                    crate::RateLimitReceipt::default(),
                    Some("BLOCKED_ENV".to_owned()),
                    TransportProvenance::BlockedEnv,
                ),
                NcbiEutilsProviderError::Timeout => (
                    PubMedEvidenceState::ProviderUnknown,
                    0,
                    sha256_digest(b"TIMEOUT"),
                    0,
                    crate::RateLimitReceipt::default(),
                    Some("transport_timeout".to_owned()),
                    provenance,
                ),
                NcbiEutilsProviderError::ProviderUnknown => (
                    PubMedEvidenceState::ProviderUnknown,
                    0,
                    sha256_digest(b"PROVIDER_UNKNOWN"),
                    0,
                    crate::RateLimitReceipt::default(),
                    Some("provider_unknown".to_owned()),
                    provenance,
                ),
                NcbiEutilsProviderError::CursorReplay => (
                    PubMedEvidenceState::Tamper,
                    0,
                    sha256_digest(b"CURSOR_REPLAY"),
                    0,
                    crate::RateLimitReceipt::default(),
                    Some("cursor_replay".to_owned()),
                    provenance,
                ),
                NcbiEutilsProviderError::ResponseTooLarge {
                    status,
                    response_digest,
                    response_bytes,
                    rate_limit,
                    provenance,
                } => (
                    PubMedEvidenceState::ResponseTooLarge,
                    status,
                    response_digest,
                    response_bytes,
                    rate_limit,
                    Some("response_too_large".to_owned()),
                    provenance,
                ),
                NcbiEutilsProviderError::MalformedResponse {
                    status,
                    response_digest,
                    response_bytes,
                    rate_limit,
                    provenance,
                    ..
                } => (
                    PubMedEvidenceState::MalformedResponse,
                    status,
                    response_digest,
                    response_bytes,
                    rate_limit,
                    Some("malformed_response".to_owned()),
                    provenance,
                ),
                _ => (
                    PubMedEvidenceState::ProviderUnknown,
                    0,
                    sha256_digest(b"PROVIDER_ERROR"),
                    0,
                    crate::RateLimitReceipt::default(),
                    Some("provider_error".to_owned()),
                    provenance,
                ),
            };
        self.build_evidence(
            state,
            status,
            response_digest,
            response_bytes,
            rate_limit,
            provenance,
            self.scope().query().operation(),
            self.scope().database(),
            self.scope().query().selector_digest().to_owned(),
            self.scope().query().pmid_digest().map(str::to_owned),
            self.scope().query().pmcid_digest().map(str::to_owned),
            self.scope().query().mesh_digest().map(str::to_owned),
            None,
            Vec::new(),
            Vec::new(),
            None,
            None,
            sha256_digest(b"NO_PAGE"),
            request_digest,
            idempotency_digest,
            reason,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build_evidence(
        &self,
        state: PubMedEvidenceState,
        status: u16,
        response_digest: Digest,
        response_bytes: usize,
        rate_limit: crate::RateLimitReceipt,
        provenance: TransportProvenance,
        operation: crate::PubMedOperation,
        database: crate::PubMedDatabase,
        query_digest: Digest,
        pmid_digest: Option<Digest>,
        pmcid_digest: Option<Digest>,
        mesh_digest: Option<Digest>,
        total_results: Option<u64>,
        articles: Vec<crate::PubMedArticleProjection>,
        links: Vec<crate::PubMedLinkProjection>,
        cursor_digest: Option<Digest>,
        history_digest: Option<Digest>,
        page_digest: Digest,
        request_digest: Digest,
        idempotency_digest: Digest,
        partial_reason: Option<String>,
    ) -> PubMedResearchEvidence {
        let read_receipt = PubMedReadReceipt {
            status,
            response_digest: response_digest.clone(),
            response_bytes: response_bytes.min(MAX_RESPONSE_BYTES),
            rate_limit_digest: rate_limit.digest(),
            provenance,
            request_digest: request_digest.clone(),
            idempotency_digest: idempotency_digest.clone(),
            cursor_digest: cursor_digest.clone(),
            history_digest: history_digest.clone(),
            connected: false,
            native: false,
            first_party: false,
        };
        let mut evidence = PubMedResearchEvidence {
            operation,
            database,
            query_digest,
            pmid_digest,
            pmcid_digest,
            mesh_digest,
            scope_digest: self.scope().digest(),
            consent_digest: self.scope().consent().digest(),
            provider_digest: self.provider.provider_digest(),
            registration_digest: self.registration().registration_digest.clone(),
            response_digest,
            state,
            total_results,
            returned_results: articles.len() + links.len(),
            articles,
            links,
            partial_reason,
            rate_limit,
            read_receipt,
            cursor_digest,
            history_digest,
            page_digest,
            request_digest,
            idempotency_digest,
            evidence_digest: String::new(),
        };
        if evidence.page_digest == sha256_digest(b"NO_PAGE") {
            evidence.page_digest = page_digest_from_evidence(&evidence);
        }
        evidence.evidence_digest = evidence.digest();
        evidence
    }
}

fn recommendation_for(evidence: &PubMedResearchEvidence) -> RecommendationDisposition {
    match evidence.state {
        PubMedEvidenceState::Complete | PubMedEvidenceState::Partial => {
            RecommendationDisposition::ReviewMetadata
        }
        PubMedEvidenceState::Empty => RecommendationDisposition::NoResults,
        PubMedEvidenceState::Denied => RecommendationDisposition::AccessDenied,
        PubMedEvidenceState::RateLimited => RecommendationDisposition::RetryAfterRateLimit,
        PubMedEvidenceState::Tamper => RecommendationDisposition::TamperRejected,
        PubMedEvidenceState::ProviderUnknown
        | PubMedEvidenceState::BlockedEnv
        | PubMedEvidenceState::MalformedResponse
        | PubMedEvidenceState::ResponseTooLarge => RecommendationDisposition::ProviderUnavailable,
    }
}

fn page_digest_from_evidence(evidence: &PubMedResearchEvidence) -> Digest {
    canonical_digest(&(
        evidence.operation,
        evidence.database,
        &evidence.query_digest,
        &evidence.total_results,
        &evidence.articles,
        &evidence.links,
        &matches!(evidence.state, PubMedEvidenceState::Partial),
        &evidence.cursor_digest,
        &evidence.history_digest,
        evidence.read_receipt.response_bytes,
        &evidence.request_digest,
        &evidence.idempotency_digest,
    ))
}

fn map_provider_error(error: NcbiEutilsProviderError) -> PubMedResearchResultServiceError {
    match error {
        NcbiEutilsProviderError::RegistrationRevoked => {
            PubMedResearchResultServiceError::RegistrationRevoked
        }
        NcbiEutilsProviderError::RegistrationDrift
        | NcbiEutilsProviderError::ProviderDefinitionDrift
        | NcbiEutilsProviderError::RequestNotAllowlisted => {
            PubMedResearchResultServiceError::RegistrationDrift
        }
        NcbiEutilsProviderError::SecretRevoked => PubMedResearchResultServiceError::SecretRevoked,
        NcbiEutilsProviderError::MissingMetadataPermission => {
            PubMedResearchResultServiceError::MissingMetadataPermission
        }
        NcbiEutilsProviderError::ScopeMismatch => PubMedResearchResultServiceError::ScopeMismatch,
        NcbiEutilsProviderError::CursorMismatch => PubMedResearchResultServiceError::CursorMismatch,
        NcbiEutilsProviderError::HistoryMismatch => {
            PubMedResearchResultServiceError::HistoryMismatch
        }
        NcbiEutilsProviderError::CursorReplay => PubMedResearchResultServiceError::ReplayDetected,
        NcbiEutilsProviderError::Model(error) => PubMedResearchResultServiceError::Model(error),
        _ => PubMedResearchResultServiceError::RegistrationDrift,
    }
}

fn map_registration_error(error: ModelError) -> PubMedResearchResultServiceError {
    match error {
        ModelError::AlreadyRevoked => PubMedResearchResultServiceError::RegistrationRevoked,
        ModelError::InvalidScope("secret reference revoked") => {
            PubMedResearchResultServiceError::SecretRevoked
        }
        _ => PubMedResearchResultServiceError::RegistrationDrift,
    }
}

fn map_transition_error(error: ModelError) -> PubMedResearchResultServiceError {
    match error {
        ModelError::AlreadyRevoked => PubMedResearchResultServiceError::RegistrationRevoked,
        ModelError::NotRevoked => PubMedResearchResultServiceError::RegistrationDrift,
        other => PubMedResearchResultServiceError::Model(other),
    }
}

fn transition_receipt(
    from: RegistrationState,
    to: RegistrationState,
    registration: &PubMedRegistration,
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

pub type PubMedService<T> = PubMedResearchResultService<T>;
pub type PubMedServiceError = PubMedResearchResultServiceError;
pub type PubMedEvidence = PubMedResearchEvidence;
pub type PubMedProposal = PubMedResearchProposal;
pub type PubMedReceipt = PubMedObservationReceipt;
