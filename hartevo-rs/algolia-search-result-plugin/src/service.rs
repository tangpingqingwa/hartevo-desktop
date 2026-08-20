use std::fmt;

use thiserror::Error;

use crate::{
    ALGOLIA_ANALYTICS_PROVIDER_ID, ALGOLIA_ANALYTICS_PROVIDER_VERSION,
    ALGOLIA_SEARCH_RESULT_CONTRACT_VERSION, ALGOLIA_SEARCH_RESULT_PLUGIN_VERSION,
    ALGOLIA_SEARCH_RESULT_SCHEMA_VERSION, AlgoliaAnalyticsProvider, AlgoliaAnalyticsRequest,
    AlgoliaAnalyticsRequestReceipt, AlgoliaAnalyticsTransport, AlgoliaEvidenceDigests,
    AlgoliaEvidenceState, AlgoliaProviderError, AlgoliaRateLimitReceipt, AlgoliaReadbackReceipt,
    AlgoliaRegistration, AlgoliaSearchQualityAggregate, AlgoliaSearchQualityEvidence,
    AlgoliaSearchQualityMetric, AlgoliaSearchQualityProposal, AlgoliaSearchQualityRecommendation,
    AlgoliaSearchQualityScope, ConsentScope, Digest, EvidenceClassification, MAX_RESPONSE_BYTES,
    MISSION_ALGOLIA_SEARCH_CONSUMER_ID, ModelError, ObservationReceipt, RecommendationDisposition,
    TransportProvenance, canonical_digest,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AlgoliaSearchQualityServiceError {
    #[error("Algolia registration is revoked or drifted")]
    RegistrationRevoked,
    #[error("Algolia SecretReference is revoked")]
    SecretRevoked,
    #[error("Algolia Analytics ACL is missing")]
    MissingAnalyticsAcl,
    #[error("Algolia scope or region binding does not match")]
    ScopeMismatch,
    #[error("Algolia read consent is denied or stale")]
    ConsentMismatch,
    #[error("Algolia evidence or proposal digest fence failed")]
    EvidenceMismatch,
    #[error("Algolia proposal replay was rejected")]
    ReplayDetected,
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AlgoliaSearchQualityServiceDefinition {
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
}

impl Default for AlgoliaSearchQualityServiceDefinition {
    fn default() -> Self {
        Self {
            schema_version: ALGOLIA_SEARCH_RESULT_SCHEMA_VERSION.to_owned(),
            contract_version: ALGOLIA_SEARCH_RESULT_CONTRACT_VERSION.to_owned(),
            service_id: crate::ALGOLIA_SEARCH_QUALITY_SERVICE_ID.to_owned(),
            provider_id: ALGOLIA_ANALYTICS_PROVIDER_ID.to_owned(),
            consumer_id: MISSION_ALGOLIA_SEARCH_CONSUMER_ID.to_owned(),
            contract_digest: crate::contract_digest(),
            read_only: true,
            live_execution: false,
            emits_outcome: false,
            external_writes: false,
        }
    }
}

/// Layer-1 typed service for read-only, aggregate Algolia search-quality
/// evidence. Native HTTPS and credential resolution remain Layer-2 seams.
pub struct AlgoliaSearchQualityService<T: AlgoliaAnalyticsTransport> {
    provider: AlgoliaAnalyticsProvider<T>,
    definition: AlgoliaSearchQualityServiceDefinition,
}

impl<T: AlgoliaAnalyticsTransport> fmt::Debug for AlgoliaSearchQualityService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AlgoliaSearchQualityService")
            .field("provider", &self.provider)
            .field("definition", &self.definition)
            .finish()
    }
}

impl<T: AlgoliaAnalyticsTransport> AlgoliaSearchQualityService<T> {
    pub fn new(
        provider: AlgoliaAnalyticsProvider<T>,
    ) -> Result<Self, AlgoliaSearchQualityServiceError> {
        provider
            .registration()
            .validate(
                provider.scope(),
                provider.secret_reference(),
                &provider.provider_digest(),
            )
            .map_err(|_| AlgoliaSearchQualityServiceError::RegistrationRevoked)?;
        Ok(Self {
            provider,
            definition: AlgoliaSearchQualityServiceDefinition::default(),
        })
    }

    #[must_use]
    pub fn from_provider(provider: AlgoliaAnalyticsProvider<T>) -> Self {
        Self {
            provider,
            definition: AlgoliaSearchQualityServiceDefinition::default(),
        }
    }

    #[must_use]
    pub fn provider(&self) -> &AlgoliaAnalyticsProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut AlgoliaAnalyticsProvider<T> {
        &mut self.provider
    }

    #[must_use]
    pub fn scope(&self) -> &AlgoliaSearchQualityScope {
        self.provider.scope()
    }

    #[must_use]
    pub fn registration(&self) -> &AlgoliaRegistration {
        self.provider.registration()
    }

    #[must_use]
    pub fn service_definition(&self) -> &AlgoliaSearchQualityServiceDefinition {
        &self.definition
    }

    /// A typed consent envelope. It is a scope check, not proof of a native
    /// consent dialog or a native credential flow.
    #[must_use]
    pub fn issue_read_consent(&self) -> ConsentScope {
        self.scope().consent().clone()
    }

    pub fn read(
        &mut self,
    ) -> Result<AlgoliaSearchQualityEvidence, AlgoliaSearchQualityServiceError> {
        let consent = self.issue_read_consent();
        self.read_with_consent(&consent)
    }

    pub fn read_with_consent(
        &mut self,
        consent: &ConsentScope,
    ) -> Result<AlgoliaSearchQualityEvidence, AlgoliaSearchQualityServiceError> {
        self.validate_consent(consent)?;
        match self.provider.read() {
            Ok(read) => Ok(normalize_success(
                self.scope(),
                self.registration(),
                self.provider.provider_digest(),
                read,
            )),
            Err(AlgoliaProviderError::RegistrationRevoked) => {
                Err(AlgoliaSearchQualityServiceError::RegistrationRevoked)
            }
            Err(AlgoliaProviderError::SecretRevoked) => {
                Err(AlgoliaSearchQualityServiceError::SecretRevoked)
            }
            Err(AlgoliaProviderError::MissingAnalyticsAcl) => {
                Err(AlgoliaSearchQualityServiceError::MissingAnalyticsAcl)
            }
            Err(AlgoliaProviderError::ScopeMismatch) => {
                Err(AlgoliaSearchQualityServiceError::ScopeMismatch)
            }
            Err(error) => Ok(normalize_failure(
                self.scope(),
                self.registration(),
                self.provider.provider_digest(),
                self.provider.transport_provenance(),
                &error,
            )),
        }
    }

    pub fn compile_proposal(
        &mut self,
    ) -> Result<AlgoliaSearchQualityProposal, AlgoliaSearchQualityServiceError> {
        let evidence = self.read()?;
        self.compile_proposal_from_evidence(evidence)
    }

    pub fn compile_search_quality_proposal(
        &mut self,
    ) -> Result<AlgoliaSearchQualityProposal, AlgoliaSearchQualityServiceError> {
        self.compile_proposal()
    }

    pub fn compile_proposal_with_consent(
        &mut self,
        consent: &ConsentScope,
    ) -> Result<AlgoliaSearchQualityProposal, AlgoliaSearchQualityServiceError> {
        let evidence = self.read_with_consent(consent)?;
        self.compile_proposal_from_evidence(evidence)
    }

    pub fn compile_proposal_from_evidence(
        &self,
        evidence: AlgoliaSearchQualityEvidence,
    ) -> Result<AlgoliaSearchQualityProposal, AlgoliaSearchQualityServiceError> {
        self.ensure_registration()?;
        self.verify_evidence(&evidence)?;
        let recommendation = recommendation_for(self.scope(), &evidence);
        let source_evidence_digest = evidence.digest();
        let mut proposal = AlgoliaSearchQualityProposal {
            scope: self.scope().clone(),
            evidence,
            source_evidence_digest,
            registration_digest: self.registration().registration_digest.clone(),
            provider_digest: self.provider.provider_digest(),
            contract_digest: crate::contract_digest(),
            acl_digest: self.scope().acl_digest(),
            proposal_only: true,
            native: false,
            connected: false,
            adopts_outcome: false,
            recommendation,
            proposal_digest: String::new(),
        };
        proposal.proposal_digest = proposal.digest();
        Ok(proposal)
    }

    pub fn verify_proposal(
        &self,
        proposal: &AlgoliaSearchQualityProposal,
    ) -> Result<(), AlgoliaSearchQualityServiceError> {
        self.ensure_registration()?;
        if !proposal.proposal_only
            || proposal.native
            || proposal.connected
            || proposal.adopts_outcome
            || proposal.scope != *self.scope()
            || proposal.registration_digest != self.registration().registration_digest
            || proposal.provider_digest != self.provider.provider_digest()
            || proposal.contract_digest != crate::contract_digest()
            || proposal.acl_digest != self.scope().acl_digest()
            || proposal.source_evidence_digest != proposal.evidence.digest()
            || proposal.proposal_digest != proposal.digest()
        {
            return Err(AlgoliaSearchQualityServiceError::EvidenceMismatch);
        }
        self.verify_evidence(&proposal.evidence)
    }

    pub fn record_observation(
        &self,
        proposal: &AlgoliaSearchQualityProposal,
    ) -> Result<ObservationReceipt, AlgoliaSearchQualityServiceError> {
        self.verify_proposal(proposal)?;
        Ok(ObservationReceipt {
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            recorded: true,
            durable: false,
            native: false,
            connected: false,
        })
    }

    pub fn read_back(
        &self,
        proposal: &AlgoliaSearchQualityProposal,
    ) -> Result<AlgoliaReadbackReceipt, AlgoliaSearchQualityServiceError> {
        self.verify_proposal(proposal)?;
        Ok(AlgoliaReadbackReceipt {
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            status: "verified_against_proposal".to_owned(),
            independent_native_readback: false,
            native: false,
            connected: false,
        })
    }

    pub fn revoke(
        &mut self,
    ) -> Result<crate::RegistrationRevocationReceipt, AlgoliaSearchQualityServiceError> {
        self.provider.revoke().map_err(map_provider_error)
    }

    pub fn restore(&mut self) -> Result<(), AlgoliaSearchQualityServiceError> {
        self.provider.restore().map_err(map_provider_error)
    }

    pub fn revoke_secret(&mut self) -> Result<(), AlgoliaSearchQualityServiceError> {
        self.provider.revoke_secret().map_err(map_provider_error)
    }

    fn validate_consent(
        &self,
        consent: &ConsentScope,
    ) -> Result<(), AlgoliaSearchQualityServiceError> {
        consent.validate()?;
        if consent == self.scope().consent() {
            Ok(())
        } else {
            Err(AlgoliaSearchQualityServiceError::ConsentMismatch)
        }
    }

    fn ensure_registration(&self) -> Result<(), AlgoliaSearchQualityServiceError> {
        self.registration()
            .validate(
                self.scope(),
                self.provider.secret_reference(),
                &self.provider.provider_digest(),
            )
            .map_err(|_| AlgoliaSearchQualityServiceError::RegistrationRevoked)
    }

    fn verify_evidence(
        &self,
        evidence: &AlgoliaSearchQualityEvidence,
    ) -> Result<(), AlgoliaSearchQualityServiceError> {
        if evidence.evidence_digest != evidence.digest()
            || evidence.scope_digest != *self.scope().scope_digest()
            || evidence.revision_digest != *self.scope().revision_digest()
            || evidence.privacy_digest != *self.scope().privacy_digest()
            || evidence.metric != self.scope().metric()
            || evidence.analytics_window != *self.scope().analytics_window()
            || evidence.provenance.is_native()
            || evidence.provenance.is_connected()
            || evidence.native
            || evidence.connected
            || evidence.digests.contract_digest != crate::contract_digest()
            || evidence.digests.plugin_version_digest
                != canonical_digest(&ALGOLIA_SEARCH_RESULT_PLUGIN_VERSION)
            || evidence.digests.provider_digest != self.provider.provider_digest()
            || evidence.digests.acl_digest != self.scope().acl_digest()
            || evidence.digests.scope_digest != *self.scope().scope_digest()
            || evidence.digests.revision_digest != *self.scope().revision_digest()
            || evidence.digests.privacy_digest != *self.scope().privacy_digest()
            || evidence.digests.registration_digest != self.registration().registration_digest
            || evidence.digests.index_digest != self.scope().index_name().digest()
            || evidence.digests.analytics_window_digest != self.scope().analytics_window().digest()
            || evidence.digests.metric_digest != self.scope().metric().digest()
            || evidence.digests.query_digest != evidence.read_receipt.request_digest
            || evidence.digests.response_digest != evidence.read_receipt.response_digest
            || evidence.read_receipt.method != crate::AlgoliaHttpMethod::Get
            || evidence.read_receipt.endpoint != self.scope().metric().endpoint()
            || evidence.read_receipt.rate_limit_digest != evidence.rate_limit.digest()
            || evidence
                .aggregate
                .as_ref()
                .is_some_and(|aggregate| evidence.digests.result_digest != aggregate.digest())
            || evidence.aggregate.is_none()
                && evidence.digests.result_digest
                    != canonical_digest(&("no-aggregate", &evidence.read_receipt.response_digest))
        {
            return Err(AlgoliaSearchQualityServiceError::EvidenceMismatch);
        }
        Ok(())
    }
}

fn map_provider_error(error: AlgoliaProviderError) -> AlgoliaSearchQualityServiceError {
    match error {
        AlgoliaProviderError::RegistrationRevoked => {
            AlgoliaSearchQualityServiceError::RegistrationRevoked
        }
        AlgoliaProviderError::SecretRevoked => AlgoliaSearchQualityServiceError::SecretRevoked,
        AlgoliaProviderError::MissingAnalyticsAcl => {
            AlgoliaSearchQualityServiceError::MissingAnalyticsAcl
        }
        AlgoliaProviderError::ScopeMismatch => AlgoliaSearchQualityServiceError::ScopeMismatch,
        AlgoliaProviderError::Model(error) => AlgoliaSearchQualityServiceError::Model(error),
        AlgoliaProviderError::RateLimited { .. }
        | AlgoliaProviderError::HttpStatus { .. }
        | AlgoliaProviderError::ResponseTooLarge { .. }
        | AlgoliaProviderError::MalformedResponse { .. }
        | AlgoliaProviderError::InvalidRateLimitReceipt { .. }
        | AlgoliaProviderError::Transport { .. } => {
            AlgoliaSearchQualityServiceError::EvidenceMismatch
        }
    }
}

fn normalize_success(
    scope: &AlgoliaSearchQualityScope,
    registration: &AlgoliaRegistration,
    provider_digest: Digest,
    read: crate::AlgoliaProviderRead,
) -> AlgoliaSearchQualityEvidence {
    let state = if read.aggregate.is_empty() {
        AlgoliaEvidenceState::Empty
    } else if read.aggregate.partial {
        AlgoliaEvidenceState::Partial
    } else {
        AlgoliaEvidenceState::Complete
    };
    let classification = if state == AlgoliaEvidenceState::Empty {
        EvidenceClassification::Empty
    } else {
        EvidenceClassification::Normalized
    };
    let request_digest = read.request.request_digest.clone();
    let response_digest = read.response_digest.clone();
    let read_receipt = AlgoliaAnalyticsRequestReceipt {
        method: read.request.method,
        endpoint: read.request.path.clone(),
        request_digest: request_digest.clone(),
        response_digest: response_digest.clone(),
        status_code: Some(200),
        response_bytes: read.response_bytes,
        rate_limit_digest: read.rate_limit.digest(),
    };
    let digests = evidence_digests(
        scope,
        registration,
        provider_digest,
        request_digest,
        read.aggregate.digest(),
        response_digest,
    );
    evidence(
        state,
        classification,
        scope,
        Some(read.aggregate),
        read_receipt,
        read.rate_limit,
        digests,
        read.provenance,
    )
}

fn normalize_failure(
    scope: &AlgoliaSearchQualityScope,
    registration: &AlgoliaRegistration,
    provider_digest: Digest,
    provenance: TransportProvenance,
    error: &AlgoliaProviderError,
) -> AlgoliaSearchQualityEvidence {
    let request = error.request().cloned().unwrap_or_else(|| {
        let mut request = AlgoliaAnalyticsRequest {
            method: crate::AlgoliaHttpMethod::Get,
            host: scope.region().host().to_owned(),
            path: scope.metric().endpoint().to_owned(),
            application_id: scope.application_id().clone(),
            index_name: scope.index_name().clone(),
            start_date: scope.analytics_window().start_date().to_owned(),
            end_date: scope.analytics_window().end_date().to_owned(),
            metric: scope.metric(),
            tag_digests: scope
                .tags()
                .iter()
                .map(|tag| tag.digest().clone())
                .collect(),
            scope_digest: scope.digest(),
            consent_digest: scope.consent_digest().clone(),
            secret_reference_digest: canonical_digest(&"secret-reference-unavailable"),
            request_digest: String::new(),
        };
        request.request_digest = request.digest();
        request
    });
    let (response_digest, response_bytes, rate_limit, status_code) = error.metadata().unwrap_or((
        canonical_digest(&("algolia-provider-error", request.request_digest.clone())),
        0,
        AlgoliaRateLimitReceipt::default(),
        None,
    ));
    let (state, classification) = failure_state(error, provenance);
    let read_receipt = AlgoliaAnalyticsRequestReceipt {
        method: request.method,
        endpoint: request.path,
        request_digest: request.request_digest.clone(),
        response_digest: response_digest.clone(),
        status_code,
        response_bytes,
        rate_limit_digest: rate_limit.digest(),
    };
    let digests = evidence_digests(
        scope,
        registration,
        provider_digest,
        request.request_digest,
        canonical_digest(&("no-aggregate", &response_digest)),
        response_digest,
    );
    evidence(
        state,
        classification,
        scope,
        None,
        read_receipt,
        rate_limit,
        digests,
        provenance,
    )
}

fn failure_state(
    error: &AlgoliaProviderError,
    provenance: TransportProvenance,
) -> (AlgoliaEvidenceState, EvidenceClassification) {
    if matches!(error, AlgoliaProviderError::RateLimited { .. }) {
        return (
            AlgoliaEvidenceState::RateLimited,
            EvidenceClassification::RateLimited,
        );
    }
    if matches!(
        error,
        AlgoliaProviderError::Transport {
            error: crate::AlgoliaTransportError::BlockedEnv,
            ..
        }
    ) {
        return (
            AlgoliaEvidenceState::AccessLost,
            EvidenceClassification::BlockedEnv,
        );
    }
    if let AlgoliaProviderError::HttpStatus { status_code, .. } = error {
        return match status_code {
            402 => (
                AlgoliaEvidenceState::PlanUnavailable,
                EvidenceClassification::PlanUnavailable,
            ),
            401 | 403 | 404 => (
                AlgoliaEvidenceState::AccessLost,
                EvidenceClassification::AccessLost,
            ),
            429 => (
                AlgoliaEvidenceState::RateLimited,
                EvidenceClassification::RateLimited,
            ),
            _ => (
                AlgoliaEvidenceState::ProviderUnknown,
                EvidenceClassification::ProviderUnknown,
            ),
        };
    }
    if provenance.is_blocked_env() {
        (
            AlgoliaEvidenceState::AccessLost,
            EvidenceClassification::BlockedEnv,
        )
    } else {
        (
            AlgoliaEvidenceState::ProviderUnknown,
            EvidenceClassification::ProviderUnknown,
        )
    }
}

fn evidence(
    state: AlgoliaEvidenceState,
    classification: EvidenceClassification,
    scope: &AlgoliaSearchQualityScope,
    aggregate: Option<AlgoliaSearchQualityAggregate>,
    read_receipt: AlgoliaAnalyticsRequestReceipt,
    rate_limit: AlgoliaRateLimitReceipt,
    digests: AlgoliaEvidenceDigests,
    provenance: TransportProvenance,
) -> AlgoliaSearchQualityEvidence {
    let mut evidence = AlgoliaSearchQualityEvidence {
        state,
        classification,
        metric: scope.metric(),
        analytics_window: scope.analytics_window().clone(),
        scope_digest: scope.digest(),
        revision_digest: scope.revision_digest().clone(),
        privacy_digest: scope.privacy_digest().clone(),
        aggregate,
        read_receipt,
        rate_limit,
        digests,
        provenance,
        proposal_only: true,
        native: false,
        connected: false,
        content_quality_claim: false,
        relevance_causality_claim: false,
        purchase_intent_claim: false,
        business_success_claim: false,
        evidence_digest: String::new(),
    };
    evidence.evidence_digest = evidence.digest();
    evidence
}

fn evidence_digests(
    scope: &AlgoliaSearchQualityScope,
    registration: &AlgoliaRegistration,
    provider_digest: Digest,
    query_digest: Digest,
    result_digest: Digest,
    response_digest: Digest,
) -> AlgoliaEvidenceDigests {
    AlgoliaEvidenceDigests {
        plugin_version_digest: canonical_digest(&ALGOLIA_SEARCH_RESULT_PLUGIN_VERSION),
        contract_digest: crate::contract_digest(),
        provider_digest,
        acl_digest: scope.acl_digest(),
        scope_digest: scope.digest(),
        revision_digest: scope.revision_digest().clone(),
        privacy_digest: scope.privacy_digest().clone(),
        registration_digest: registration.registration_digest.clone(),
        index_digest: scope.index_name().digest(),
        analytics_window_digest: scope.analytics_window().digest(),
        metric_digest: scope.metric().digest(),
        query_digest,
        result_digest,
        response_digest,
    }
}

fn recommendation_for(
    scope: &AlgoliaSearchQualityScope,
    evidence: &AlgoliaSearchQualityEvidence,
) -> AlgoliaSearchQualityRecommendation {
    let disposition = match evidence.state {
        AlgoliaEvidenceState::Complete => match scope.metric() {
            AlgoliaSearchQualityMetric::SearchCount => {
                RecommendationDisposition::ReviewSearchDemand
            }
            AlgoliaSearchQualityMetric::NoResultRate => {
                RecommendationDisposition::ReviewContentCoverage
            }
            AlgoliaSearchQualityMetric::ClickThroughRate => {
                RecommendationDisposition::ReviewResultInteraction
            }
            AlgoliaSearchQualityMetric::ConversionRate => {
                RecommendationDisposition::ReviewConversionSignal
            }
        },
        AlgoliaEvidenceState::Partial => RecommendationDisposition::NoRecommendationPartial,
        AlgoliaEvidenceState::Empty => RecommendationDisposition::NoRecommendationEmpty,
        AlgoliaEvidenceState::PlanUnavailable => {
            RecommendationDisposition::NoRecommendationPlanUnavailable
        }
        AlgoliaEvidenceState::RateLimited => RecommendationDisposition::NoRecommendationRateLimited,
        AlgoliaEvidenceState::AccessLost => RecommendationDisposition::NoRecommendationAccessLost,
        AlgoliaEvidenceState::ProviderUnknown => {
            RecommendationDisposition::NoRecommendationProviderUnknown
        }
    };
    let rationale_digest = canonical_digest(&(
        "algolia-search-quality-recommendation/v1",
        scope.metric(),
        &evidence.state,
        &evidence.digests.result_digest,
        &disposition,
    ));
    AlgoliaSearchQualityRecommendation {
        disposition,
        provider_reported_only: true,
        non_mutating: true,
        claims_content_quality: false,
        claims_relevance_causality: false,
        claims_purchase_intent: false,
        claims_business_success: false,
        rationale_digest,
    }
}

// Keep this alias available for consumers that used the shorter service error
// naming in earlier Layer-1 connector crates.
pub type AlgoliaServiceError = AlgoliaSearchQualityServiceError;

#[allow(dead_code)]
fn _provider_version_is_bound() -> &'static str {
    ALGOLIA_ANALYTICS_PROVIDER_VERSION
}

#[allow(dead_code)]
fn _response_bound_is_bound() -> usize {
    MAX_RESPONSE_BYTES
}
