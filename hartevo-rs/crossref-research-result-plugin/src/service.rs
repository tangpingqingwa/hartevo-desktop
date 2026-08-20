use std::fmt;

use thiserror::Error;

use crate::{
    CROSSREF_RESEARCH_RESULT_CONTRACT_VERSION, CROSSREF_RESEARCH_RESULT_SCHEMA_VERSION,
    CrossrefEvidenceState, CrossrefObservationReceipt, CrossrefPermission, CrossrefProvider,
    CrossrefProviderError, CrossrefProviderRead, CrossrefReadReceipt, CrossrefRegistration,
    CrossrefResearchEvidence, CrossrefResearchProposal, CrossrefResearchScope, CrossrefTransport,
    Digest, MAX_RESPONSE_BYTES, MISSION_CROSSREF_RESEARCH_CONSUMER_ID, ModelError,
    RecommendationDisposition, RegistrationState, RegistrationTransitionReceipt,
    TransportProvenance, sha256_digest,
};

pub const CROSSREF_RESEARCH_RESULT_SERVICE_ID: &str = "crossref.research-result";

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CrossrefResearchResultServiceError {
    #[error("Crossref registration is revoked")]
    RegistrationRevoked,
    #[error("Crossref registration is stale, tampered, or drifted")]
    RegistrationDrift,
    #[error("Crossref SecretReference is revoked")]
    SecretRevoked,
    #[error("Crossref metadata.read permission is missing")]
    MissingMetadataPermission,
    #[error("Crossref scope is stale or does not match the service")]
    ScopeMismatch,
    #[error("Crossref read consent is denied or stale")]
    ConsentMismatch,
    #[error("Crossref evidence digest or binding verification failed")]
    EvidenceMismatch,
    #[error("Crossref proposal digest or binding verification failed")]
    ProposalMismatch,
    #[error("Crossref proposal replay or stale registration was rejected")]
    ReplayDetected,
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrossrefResearchResultServiceDefinition {
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

impl Default for CrossrefResearchResultServiceDefinition {
    fn default() -> Self {
        Self {
            schema_version: CROSSREF_RESEARCH_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: CROSSREF_RESEARCH_RESULT_CONTRACT_VERSION.to_owned(),
            service_id: CROSSREF_RESEARCH_RESULT_SERVICE_ID.to_owned(),
            provider_id: crate::CROSSREF_PROVIDER_ID.to_owned(),
            consumer_id: MISSION_CROSSREF_RESEARCH_CONSUMER_ID.to_owned(),
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

/// Typed Layer-1 service for bounded Crossref metadata evidence. It prepares
/// proposals and observation receipts but never creates a kernel receipt,
/// claims Truth, or adopts a Work Product/Outcome.
pub struct CrossrefResearchResultService<T: CrossrefTransport> {
    provider: CrossrefProvider<T>,
    definition: CrossrefResearchResultServiceDefinition,
}

impl<T: CrossrefTransport> fmt::Debug for CrossrefResearchResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CrossrefResearchResultService")
            .field("provider", &self.provider)
            .field("definition", &self.definition)
            .finish()
    }
}

impl<T: CrossrefTransport> CrossrefResearchResultService<T> {
    pub fn new(provider: CrossrefProvider<T>) -> Result<Self, CrossrefResearchResultServiceError> {
        provider
            .registration()
            .validate(
                provider.scope(),
                provider.permission(),
                provider.secret_reference(),
                &provider.provider_digest(),
            )
            .map_err(|error| match error {
                ModelError::AlreadyRevoked => {
                    CrossrefResearchResultServiceError::RegistrationRevoked
                }
                ModelError::InvalidScope("secret reference revoked") => {
                    CrossrefResearchResultServiceError::SecretRevoked
                }
                _ => CrossrefResearchResultServiceError::RegistrationDrift,
            })?;
        Ok(Self {
            provider,
            definition: CrossrefResearchResultServiceDefinition::default(),
        })
    }

    #[must_use]
    pub fn from_provider(provider: CrossrefProvider<T>) -> Self {
        Self {
            provider,
            definition: CrossrefResearchResultServiceDefinition::default(),
        }
    }

    #[must_use]
    pub fn provider(&self) -> &CrossrefProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut CrossrefProvider<T> {
        &mut self.provider
    }

    #[must_use]
    pub fn scope(&self) -> &CrossrefResearchScope {
        self.provider.scope()
    }

    #[must_use]
    pub fn permission(&self) -> &CrossrefPermission {
        self.provider.permission()
    }

    #[must_use]
    pub fn registration(&self) -> &CrossrefRegistration {
        self.provider.registration()
    }

    #[must_use]
    pub fn service_definition(&self) -> &CrossrefResearchResultServiceDefinition {
        &self.definition
    }

    #[must_use]
    pub fn issue_read_consent(&self) -> crate::ConsentScope {
        self.scope().consent().clone()
    }

    pub fn read(&mut self) -> Result<CrossrefResearchEvidence, CrossrefResearchResultServiceError> {
        let consent = self.issue_read_consent();
        self.read_with_consent(&consent)
    }

    pub fn read_with_consent(
        &mut self,
        consent: &crate::ConsentScope,
    ) -> Result<CrossrefResearchEvidence, CrossrefResearchResultServiceError> {
        self.validate_consent(consent)?;
        match self.provider.read() {
            Ok(read) => Ok(self.evidence_from_read(read)),
            Err(CrossrefProviderError::RegistrationRevoked) => {
                Err(CrossrefResearchResultServiceError::RegistrationRevoked)
            }
            Err(
                CrossrefProviderError::RegistrationDrift
                | CrossrefProviderError::ProviderDefinitionDrift
                | CrossrefProviderError::RequestNotAllowlisted,
            ) => Err(CrossrefResearchResultServiceError::RegistrationDrift),
            Err(CrossrefProviderError::SecretRevoked) => {
                Err(CrossrefResearchResultServiceError::SecretRevoked)
            }
            Err(CrossrefProviderError::MissingMetadataPermission) => {
                Err(CrossrefResearchResultServiceError::MissingMetadataPermission)
            }
            Err(CrossrefProviderError::ScopeMismatch) => {
                Err(CrossrefResearchResultServiceError::ScopeMismatch)
            }
            Err(error) => Ok(self.failure_evidence(error)),
        }
    }

    pub fn compile_proposal(
        &mut self,
    ) -> Result<CrossrefResearchProposal, CrossrefResearchResultServiceError> {
        let evidence = self.read()?;
        self.compile_proposal_from_evidence(evidence)
    }

    pub fn compile_research_proposal(
        &mut self,
    ) -> Result<CrossrefResearchProposal, CrossrefResearchResultServiceError> {
        self.compile_proposal()
    }

    pub fn compile_proposal_with_consent(
        &mut self,
        consent: &crate::ConsentScope,
    ) -> Result<CrossrefResearchProposal, CrossrefResearchResultServiceError> {
        let evidence = self.read_with_consent(consent)?;
        self.compile_proposal_from_evidence(evidence)
    }

    pub fn compile_proposal_from_evidence(
        &self,
        evidence: CrossrefResearchEvidence,
    ) -> Result<CrossrefResearchProposal, CrossrefResearchResultServiceError> {
        self.ensure_registration()?;
        self.verify_evidence(&evidence)?;
        let mut proposal = CrossrefResearchProposal {
            scope: self.scope().clone(),
            source_evidence_digest: evidence.digest(),
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
        evidence: &CrossrefResearchEvidence,
    ) -> Result<(), CrossrefResearchResultServiceError> {
        self.ensure_registration()?;
        if evidence.evidence_digest != evidence.digest()
            || evidence.operation != self.scope().query().operation()
            || evidence.query_digest != self.scope().query().selector_digest()
            || evidence.scope_digest != self.scope().digest()
            || evidence.consent_digest != self.scope().consent().digest()
            || evidence.provider_digest != self.provider.provider_digest()
            || evidence.registration_digest != self.registration().registration_digest
            || evidence.response_digest != evidence.read_receipt.response_digest
            || evidence.read_receipt.rate_limit_digest != evidence.rate_limit.digest()
            || evidence.returned_results != evidence.works.len()
            || evidence.works.len() > self.scope().max_results()
            || evidence.read_receipt.connected
            || evidence.read_receipt.native
            || evidence.read_receipt.first_party
            || evidence.read_receipt.provenance.connected()
            || evidence.read_receipt.provenance.native()
            || evidence.read_receipt.provenance.first_party()
        {
            return Err(CrossrefResearchResultServiceError::EvidenceMismatch);
        }
        if let Some(total_results) = evidence.total_results
            && total_results < evidence.returned_results as u64
        {
            return Err(CrossrefResearchResultServiceError::EvidenceMismatch);
        }
        for work in &evidence.works {
            work.validate()
                .map_err(|_| CrossrefResearchResultServiceError::EvidenceMismatch)?;
        }
        Ok(())
    }

    pub fn verify_proposal(
        &self,
        proposal: &CrossrefResearchProposal,
    ) -> Result<(), CrossrefResearchResultServiceError> {
        self.ensure_registration()?;
        self.verify_evidence(&proposal.evidence)?;
        if proposal.proposal_digest != proposal.digest()
            || proposal.source_evidence_digest != proposal.evidence.digest()
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
            return Err(CrossrefResearchResultServiceError::ProposalMismatch);
        }
        Ok(())
    }

    pub fn record_receipt(
        &self,
        proposal: &CrossrefResearchProposal,
    ) -> Result<CrossrefObservationReceipt, CrossrefResearchResultServiceError> {
        self.verify_proposal(proposal)?;
        let mut receipt = CrossrefObservationReceipt {
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.source_evidence_digest.clone(),
            registration_digest: self.registration().registration_digest.clone(),
            provider_digest: self.provider.provider_digest(),
            response_digest: proposal.evidence.response_digest.clone(),
            state: proposal.evidence.state.clone(),
            provenance: proposal.evidence.read_receipt.provenance,
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
        proposal: &CrossrefResearchProposal,
    ) -> Result<CrossrefObservationReceipt, CrossrefResearchResultServiceError> {
        self.record_receipt(proposal)
    }

    pub fn revoke_registration(
        &mut self,
    ) -> Result<RegistrationTransitionReceipt, CrossrefResearchResultServiceError> {
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
    ) -> Result<RegistrationTransitionReceipt, CrossrefResearchResultServiceError> {
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
    ) -> Result<(), CrossrefResearchResultServiceError> {
        consent
            .validate()
            .map_err(|_| CrossrefResearchResultServiceError::ConsentMismatch)?;
        if consent.digest() != self.scope().consent().digest() {
            return Err(CrossrefResearchResultServiceError::ConsentMismatch);
        }
        Ok(())
    }

    fn ensure_registration(&self) -> Result<(), CrossrefResearchResultServiceError> {
        if !self.registration().state.is_active() {
            return Err(CrossrefResearchResultServiceError::RegistrationRevoked);
        }
        if self.provider.secret_reference().is_revoked() {
            return Err(CrossrefResearchResultServiceError::SecretRevoked);
        }
        self.registration()
            .validate(
                self.scope(),
                self.permission(),
                self.provider.secret_reference(),
                &self.provider.provider_digest(),
            )
            .map_err(|error| match error {
                ModelError::AlreadyRevoked => {
                    CrossrefResearchResultServiceError::RegistrationRevoked
                }
                ModelError::InvalidScope("secret reference revoked") => {
                    CrossrefResearchResultServiceError::SecretRevoked
                }
                _ => CrossrefResearchResultServiceError::RegistrationDrift,
            })
    }

    fn evidence_from_read(&self, read: CrossrefProviderRead) -> CrossrefResearchEvidence {
        let state = if read.rate_limit.throttled || read.status == 429 {
            CrossrefEvidenceState::RateLimited
        } else if read.status == 401 || read.status == 403 {
            CrossrefEvidenceState::AccessLost
        } else if read.status == 404 {
            CrossrefEvidenceState::Empty
        } else if !(200..300).contains(&read.status) {
            CrossrefEvidenceState::ProviderUnknown
        } else if read.works.is_empty() && read.total_results == Some(0) {
            CrossrefEvidenceState::Empty
        } else if read.partial {
            CrossrefEvidenceState::Partial
        } else {
            CrossrefEvidenceState::Complete
        };
        let reason = match state {
            CrossrefEvidenceState::Partial => Some("bounded_or_invalid_items".to_owned()),
            CrossrefEvidenceState::RateLimited => Some("provider_rate_limit".to_owned()),
            CrossrefEvidenceState::AccessLost => Some("provider_access_denied".to_owned()),
            CrossrefEvidenceState::Empty => Some("no_metadata_items".to_owned()),
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
            read.query_digest,
            read.total_results,
            read.works,
            reason,
        )
    }

    fn failure_evidence(&self, error: CrossrefProviderError) -> CrossrefResearchEvidence {
        let provenance = self.provider.transport_provenance();
        let (state, status, response_digest, response_bytes, rate_limit, reason, provenance) =
            match error {
                CrossrefProviderError::BlockedEnv => (
                    CrossrefEvidenceState::BlockedEnv,
                    0,
                    sha256_digest(b"BLOCKED_ENV"),
                    0,
                    crate::RateLimitReceipt::default(),
                    Some("BLOCKED_ENV".to_owned()),
                    TransportProvenance::BlockedEnv,
                ),
                CrossrefProviderError::Timeout => (
                    CrossrefEvidenceState::ProviderUnknown,
                    0,
                    sha256_digest(b"TIMEOUT"),
                    0,
                    crate::RateLimitReceipt::default(),
                    Some("transport_timeout".to_owned()),
                    provenance,
                ),
                CrossrefProviderError::ProviderUnknown => (
                    CrossrefEvidenceState::ProviderUnknown,
                    0,
                    sha256_digest(b"PROVIDER_UNKNOWN"),
                    0,
                    crate::RateLimitReceipt::default(),
                    Some("provider_unknown".to_owned()),
                    provenance,
                ),
                CrossrefProviderError::ResponseTooLarge {
                    status,
                    response_digest,
                    response_bytes,
                    rate_limit,
                    provenance,
                } => (
                    CrossrefEvidenceState::ResponseTooLarge,
                    status,
                    response_digest,
                    response_bytes,
                    rate_limit,
                    Some("response_too_large".to_owned()),
                    provenance,
                ),
                CrossrefProviderError::MalformedResponse {
                    status,
                    response_digest,
                    response_bytes,
                    rate_limit,
                    provenance,
                    ..
                } => (
                    CrossrefEvidenceState::MalformedResponse,
                    status,
                    response_digest,
                    response_bytes,
                    rate_limit,
                    Some("malformed_response".to_owned()),
                    provenance,
                ),
                _ => (
                    CrossrefEvidenceState::ProviderUnknown,
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
            self.scope().query().selector_digest().to_owned(),
            None,
            Vec::new(),
            reason,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build_evidence(
        &self,
        state: CrossrefEvidenceState,
        status: u16,
        response_digest: Digest,
        response_bytes: usize,
        rate_limit: crate::RateLimitReceipt,
        provenance: TransportProvenance,
        operation: crate::CrossrefOperation,
        query_digest: Digest,
        total_results: Option<u64>,
        works: Vec<crate::CrossrefWorkProjection>,
        partial_reason: Option<String>,
    ) -> CrossrefResearchEvidence {
        let read_receipt = CrossrefReadReceipt {
            status,
            response_digest: response_digest.clone(),
            response_bytes: response_bytes.min(MAX_RESPONSE_BYTES),
            rate_limit_digest: rate_limit.digest(),
            provenance,
            connected: false,
            native: false,
            first_party: false,
        };
        let mut evidence = CrossrefResearchEvidence {
            operation,
            query_digest,
            scope_digest: self.scope().digest(),
            consent_digest: self.scope().consent().digest(),
            provider_digest: self.provider.provider_digest(),
            registration_digest: self.registration().registration_digest.clone(),
            response_digest,
            state,
            total_results,
            returned_results: works.len(),
            works,
            partial_reason,
            rate_limit,
            read_receipt,
            evidence_digest: String::new(),
        };
        evidence.evidence_digest = evidence.digest();
        evidence
    }
}

fn recommendation_for(evidence: &CrossrefResearchEvidence) -> RecommendationDisposition {
    match evidence.state {
        CrossrefEvidenceState::Complete | CrossrefEvidenceState::Partial => {
            RecommendationDisposition::ReviewMetadata
        }
        CrossrefEvidenceState::Empty => RecommendationDisposition::NoMetadata,
        CrossrefEvidenceState::RateLimited => RecommendationDisposition::RetryAfterRateLimit,
        CrossrefEvidenceState::AccessLost
        | CrossrefEvidenceState::ProviderUnknown
        | CrossrefEvidenceState::BlockedEnv
        | CrossrefEvidenceState::MalformedResponse
        | CrossrefEvidenceState::ResponseTooLarge => RecommendationDisposition::ProviderUnavailable,
    }
}

fn map_transition_error(error: ModelError) -> CrossrefResearchResultServiceError {
    match error {
        ModelError::AlreadyRevoked => CrossrefResearchResultServiceError::RegistrationRevoked,
        ModelError::NotRevoked => CrossrefResearchResultServiceError::RegistrationDrift,
        other => CrossrefResearchResultServiceError::Model(other),
    }
}

fn transition_receipt(
    from: RegistrationState,
    to: RegistrationState,
    registration: &CrossrefRegistration,
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
