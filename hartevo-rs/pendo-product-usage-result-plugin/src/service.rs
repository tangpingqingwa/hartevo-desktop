use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    AdoptionMetric, Digest, EvidenceClassification, EvidenceState, MAX_REQUESTS_PER_SCOPE,
    MAX_STALENESS_SECONDS, ModelError, PendoAggregate, PendoProductUsageScope, PendoProvider,
    PendoProviderError, PendoProviderRead, PendoReadProjection, PendoReadReceipt, PendoReadRequest,
    PendoRegistration, PendoReportMetadata, PendoUsageRecommendation, PendoUsageRequest,
    ProviderErrorKind, ProviderProvenance, RecommendationDisposition, RedactionSummary,
    RegistrationRevocation, SecretReference, canonical_digest,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendoProductUsageServiceDefinition;

impl PendoProductUsageServiceDefinition {
    #[must_use]
    pub const fn id() -> &'static str {
        crate::PENDO_PRODUCT_USAGE_RESULT_SERVICE_ID
    }

    #[must_use]
    pub const fn version() -> &'static str {
        crate::PENDO_PRODUCT_USAGE_RESULT_SERVICE_VERSION
    }

    #[must_use]
    pub const fn read_only() -> bool {
        true
    }

    #[must_use]
    pub const fn live_external_io() -> bool {
        false
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum PendoProductUsageServiceError {
    #[error("model validation failed: {0}")]
    Model(#[from] ModelError),
    #[error("Pendo provider definition drifted")]
    DefinitionDrift,
    #[error("Pendo registration is revoked or invalid")]
    RegistrationRevoked,
    #[error("Pendo secret reference is revoked")]
    SecretRevoked,
    #[error("request is outside the bound Mission/Product Usage scope")]
    RequestOutOfScope,
    #[error("consent scope does not match the registration")]
    ConsentMismatch,
    #[error("Pendo evidence does not match the active registration")]
    EvidenceMismatch,
    #[error("Pendo proposal is tampered")]
    Tampered,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendoProductUsageEvidence {
    pub state: EvidenceState,
    pub classification: EvidenceClassification,
    pub projection: PendoReadProjection,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub contract_digest: Digest,
    pub contract_version: String,
    pub permission_digest: Digest,
    pub query_digest: Digest,
    pub read_receipt: PendoReadReceipt,
    pub aggregate: Option<PendoAggregate>,
    pub metadata: Option<PendoReportMetadata>,
    pub error: Option<ProviderErrorKind>,
    pub redactions: RedactionSummary,
    pub provenance: ProviderProvenance,
    pub read_only: bool,
    pub aggregate_only: bool,
    pub connected: bool,
    pub native_provider: bool,
    pub first_party: bool,
    pub external_writes: bool,
    pub raw_visitor_rows: bool,
    pub raw_pii: bool,
    pub raw_event_payloads: bool,
    pub guide_segment_mutation: bool,
    pub causal_claim: bool,
    pub evidence_digest: Digest,
}

impl PendoProductUsageEvidence {
    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(&serde_json::json!({
            "state": self.state,
            "classification": self.classification,
            "projection": self.projection,
            "scopeDigest": self.scope_digest,
            "registrationDigest": self.registration_digest,
            "providerDigest": self.provider_digest,
            "contractDigest": self.contract_digest,
            "contractVersion": self.contract_version,
            "permissionDigest": self.permission_digest,
            "queryDigest": self.query_digest,
            "readReceipt": self.read_receipt,
            "aggregate": self.aggregate,
            "metadata": self.metadata,
            "error": self.error,
            "redactions": self.redactions,
            "provenance": self.provenance,
            "readOnly": self.read_only,
            "aggregateOnly": self.aggregate_only,
            "connected": self.connected,
            "nativeProvider": self.native_provider,
            "firstParty": self.first_party,
            "externalWrites": self.external_writes,
            "rawVisitorRows": self.raw_visitor_rows,
            "rawPii": self.raw_pii,
            "rawEventPayloads": self.raw_event_payloads,
            "guideSegmentMutation": self.guide_segment_mutation,
            "causalClaim": self.causal_claim,
        }))
    }

    #[must_use]
    pub const fn is_bounded_non_native(&self) -> bool {
        self.read_only
            && self.aggregate_only
            && !self.connected
            && !self.native_provider
            && !self.first_party
            && !self.external_writes
            && !self.raw_visitor_rows
            && !self.raw_pii
            && !self.raw_event_payloads
            && !self.guide_segment_mutation
            && !self.causal_claim
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendoProductUsageProposal {
    pub scope: PendoProductUsageScope,
    pub scope_digest: Digest,
    pub evidence: PendoProductUsageEvidence,
    pub source_evidence_digest: Digest,
    pub registration_digest: Digest,
    pub provider_digest: Digest,
    pub contract_digest: Digest,
    pub contract_version: String,
    pub permission_digest: Digest,
    pub query_digest: Digest,
    pub recommendation: PendoUsageRecommendation,
    pub proposal_only: bool,
    pub read_only: bool,
    pub aggregate_only: bool,
    pub connected: bool,
    pub native_provider: bool,
    pub first_party: bool,
    pub external_writes: bool,
    pub causal_claim: bool,
    pub adopted_work_product: bool,
    pub outcome_authority: bool,
    pub proposal_digest: Digest,
}

impl PendoProductUsageProposal {
    #[must_use]
    pub fn digest(&self) -> Digest {
        canonical_digest(&serde_json::json!({
            "scope": self.scope,
            "scopeDigest": self.scope_digest,
            "evidence": self.evidence,
            "sourceEvidenceDigest": self.source_evidence_digest,
            "registrationDigest": self.registration_digest,
            "providerDigest": self.provider_digest,
            "contractDigest": self.contract_digest,
            "contractVersion": self.contract_version,
            "permissionDigest": self.permission_digest,
            "queryDigest": self.query_digest,
            "recommendation": self.recommendation,
            "proposalOnly": self.proposal_only,
            "readOnly": self.read_only,
            "aggregateOnly": self.aggregate_only,
            "connected": self.connected,
            "nativeProvider": self.native_provider,
            "firstParty": self.first_party,
            "externalWrites": self.external_writes,
            "causalClaim": self.causal_claim,
            "adoptedWorkProduct": self.adopted_work_product,
            "outcomeAuthority": self.outcome_authority,
        }))
    }

    #[must_use]
    pub fn observation_receipt(&self) -> PendoObservationReceipt {
        PendoObservationReceipt {
            proposal_digest: self.proposal_digest.clone(),
            evidence_digest: self.evidence.evidence_digest.clone(),
            registration_digest: self.registration_digest.clone(),
            recorded: true,
            durable: false,
            native: false,
            connected: false,
            independent_readback: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendoObservationReceipt {
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub recorded: bool,
    pub durable: bool,
    pub native: bool,
    pub connected: bool,
    pub independent_readback: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendoVerification {
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub contract_digest: Digest,
    pub verified: bool,
    pub tamper_evident: bool,
    pub independent_native_readback: bool,
    pub native: bool,
    pub connected: bool,
}

#[derive(Debug)]
pub struct PendoProductUsageResultService<T> {
    scope: PendoProductUsageScope,
    secret: SecretReference,
    registration: PendoRegistration,
    provider: PendoProvider<T>,
    reads: u16,
}

impl<T: crate::PendoTransport> PendoProductUsageResultService<T> {
    pub fn new(
        scope: PendoProductUsageScope,
        secret: SecretReference,
        provider: PendoProvider<T>,
    ) -> Result<Self, PendoProductUsageServiceError> {
        if secret.scope_digest() != &scope.digest() {
            return Err(PendoProductUsageServiceError::Model(
                ModelError::SecretScopeMismatch,
            ));
        }
        let registration = PendoRegistration::new(&scope, &secret, provider.provider_digest())?;
        Ok(Self {
            scope,
            secret,
            registration,
            provider,
            reads: 0,
        })
    }

    #[must_use]
    pub fn scope(&self) -> &PendoProductUsageScope {
        &self.scope
    }

    #[must_use]
    pub fn secret(&self) -> &SecretReference {
        &self.secret
    }

    #[must_use]
    pub fn registration(&self) -> &PendoRegistration {
        &self.registration
    }

    #[must_use]
    pub fn provider(&self) -> &PendoProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut PendoProvider<T> {
        &mut self.provider
    }

    #[must_use]
    pub const fn service_definition(&self) -> PendoProductUsageServiceDefinition {
        PendoProductUsageServiceDefinition
    }

    pub fn read(
        &mut self,
        request: &PendoUsageRequest,
    ) -> Result<PendoProductUsageEvidence, PendoProductUsageServiceError> {
        self.ensure_registration()?;
        request
            .validate(&self.scope)
            .map_err(|_| PendoProductUsageServiceError::RequestOutOfScope)?;
        let read_request = PendoReadRequest::new(&self.scope, request, self.secret.digest())?;
        if self.reads >= MAX_REQUESTS_PER_SCOPE {
            return Ok(failure_evidence(
                &self.scope,
                &self.registration,
                self.provider.provider_digest(),
                &read_request,
                self.provider.provenance(),
                EvidenceState::RateLimited,
                EvidenceClassification::RateLimited,
                ProviderErrorKind::RateLimited,
                None,
                None,
                RedactionSummary {
                    raw_response_body_dropped: true,
                    ..RedactionSummary::default()
                },
            ));
        }
        self.reads = self.reads.saturating_add(1);
        match self.provider.read(&read_request) {
            Ok(read) => Ok(success_evidence(
                &self.scope,
                &self.registration,
                self.provider.provider_digest(),
                read,
            )),
            Err(error) => Ok(failure_from_provider(
                &self.scope,
                &self.registration,
                self.provider.provider_digest(),
                &read_request,
                self.provider.provenance(),
                error,
            )),
        }
    }

    pub fn read_aggregate(
        &mut self,
        metric: AdoptionMetric,
        requested_at: crate::Timestamp,
    ) -> Result<PendoProductUsageEvidence, PendoProductUsageServiceError> {
        let request = PendoUsageRequest::aggregate(&self.scope, metric, requested_at)?;
        self.read(&request)
    }

    pub fn read_report_metadata(
        &mut self,
        requested_at: crate::Timestamp,
    ) -> Result<PendoProductUsageEvidence, PendoProductUsageServiceError> {
        let request = PendoUsageRequest::report_metadata(&self.scope, requested_at)?;
        self.read(&request)
    }

    pub fn propose(
        &mut self,
        request: &PendoUsageRequest,
    ) -> Result<PendoProductUsageProposal, PendoProductUsageServiceError> {
        let evidence = self.read(request)?;
        self.compile_proposal_from_evidence(evidence)
    }

    pub fn compile_proposal(
        &mut self,
        request: &PendoUsageRequest,
    ) -> Result<PendoProductUsageProposal, PendoProductUsageServiceError> {
        self.propose(request)
    }

    pub fn compile_proposal_from_evidence(
        &self,
        evidence: PendoProductUsageEvidence,
    ) -> Result<PendoProductUsageProposal, PendoProductUsageServiceError> {
        self.ensure_registration()?;
        self.verify_evidence(&evidence)?;
        let mut proposal = PendoProductUsageProposal {
            scope: self.scope.clone(),
            scope_digest: self.scope.digest(),
            source_evidence_digest: evidence.evidence_digest.clone(),
            registration_digest: self.registration.registration_digest().clone(),
            provider_digest: self.provider.provider_digest(),
            contract_digest: crate::contract_digest(),
            contract_version: crate::PENDO_PRODUCT_USAGE_RESULT_CONTRACT_VERSION.to_owned(),
            permission_digest: evidence.permission_digest.clone(),
            query_digest: evidence.query_digest.clone(),
            recommendation: recommendation_for(&self.scope, evidence.state, &evidence.projection),
            proposal_only: true,
            read_only: true,
            aggregate_only: true,
            connected: false,
            native_provider: false,
            first_party: false,
            external_writes: false,
            causal_claim: false,
            adopted_work_product: false,
            outcome_authority: false,
            evidence,
            proposal_digest: String::new(),
        };
        proposal.proposal_digest = proposal.digest();
        Ok(proposal)
    }

    pub fn verify_proposal(
        &self,
        proposal: &PendoProductUsageProposal,
    ) -> Result<PendoVerification, PendoProductUsageServiceError> {
        self.ensure_registration()?;
        if proposal.scope != self.scope
            || proposal.scope_digest != self.scope.digest()
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.provider_digest != self.provider.provider_digest()
            || proposal.contract_digest != crate::contract_digest()
            || proposal.contract_version != crate::PENDO_PRODUCT_USAGE_RESULT_CONTRACT_VERSION
            || proposal.permission_digest != *self.registration.permission_digest()
            || proposal.query_digest != proposal.evidence.query_digest
            || proposal.source_evidence_digest != proposal.evidence.evidence_digest
            || proposal.proposal_digest != proposal.digest()
            || !proposal.proposal_only
            || !proposal.read_only
            || !proposal.aggregate_only
            || proposal.connected
            || proposal.native_provider
            || proposal.first_party
            || proposal.external_writes
            || proposal.causal_claim
            || proposal.adopted_work_product
            || proposal.outcome_authority
            || !proposal.evidence.is_bounded_non_native()
        {
            return Err(PendoProductUsageServiceError::EvidenceMismatch);
        }
        self.verify_evidence(&proposal.evidence)?;
        Ok(PendoVerification {
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            contract_digest: crate::contract_digest(),
            verified: true,
            tamper_evident: true,
            independent_native_readback: false,
            native: false,
            connected: false,
        })
    }

    pub fn record_observation(
        &self,
        proposal: &PendoProductUsageProposal,
    ) -> Result<PendoObservationReceipt, PendoProductUsageServiceError> {
        self.verify_proposal(proposal)?;
        Ok(proposal.observation_receipt())
    }

    pub fn revoke_registration(
        &mut self,
    ) -> Result<RegistrationRevocation, PendoProductUsageServiceError> {
        Ok(self.registration.revoke()?)
    }

    pub fn restore_registration(
        &mut self,
    ) -> Result<RegistrationRevocation, PendoProductUsageServiceError> {
        Ok(self.registration.restore()?)
    }

    pub fn revoke_secret(&mut self) -> Result<(), PendoProductUsageServiceError> {
        Ok(self.secret.revoke()?)
    }

    pub fn restore_secret(&mut self) -> Result<(), PendoProductUsageServiceError> {
        Ok(self.secret.restore()?)
    }

    fn ensure_registration(&self) -> Result<(), PendoProductUsageServiceError> {
        if self.secret.is_revoked() {
            return Err(PendoProductUsageServiceError::SecretRevoked);
        }
        self.registration
            .validate(&self.scope, &self.secret, &self.provider.provider_digest())
            .map_err(|_| PendoProductUsageServiceError::RegistrationRevoked)
    }

    fn verify_evidence(
        &self,
        evidence: &PendoProductUsageEvidence,
    ) -> Result<(), PendoProductUsageServiceError> {
        if evidence.evidence_digest != evidence.digest()
            || evidence.scope_digest != self.scope.digest()
            || evidence.registration_digest != *self.registration.registration_digest()
            || evidence.provider_digest != self.provider.provider_digest()
            || evidence.contract_digest != crate::contract_digest()
            || evidence.contract_version != crate::PENDO_PRODUCT_USAGE_RESULT_CONTRACT_VERSION
            || evidence.permission_digest != *self.registration.permission_digest()
            || evidence.query_digest != evidence.read_receipt.request_digest
            || evidence.read_receipt.secret_reference_digest != self.secret.digest()
            || evidence.read_receipt.request_digest.is_empty()
            || evidence.read_receipt.body_retained
            || !evidence.is_bounded_non_native()
        {
            return Err(PendoProductUsageServiceError::EvidenceMismatch);
        }
        Ok(())
    }
}

fn success_evidence(
    scope: &PendoProductUsageScope,
    registration: &PendoRegistration,
    provider_digest: Digest,
    read: PendoProviderRead,
) -> PendoProductUsageEvidence {
    let state = if read.as_of.is_some_and(|as_of| {
        read.request
            .requested_at()
            .unix_seconds()
            .saturating_sub(as_of.unix_seconds())
            > MAX_STALENESS_SECONDS
    }) {
        EvidenceState::Stale
    } else {
        match &read.payload {
            crate::PendoPayload::Aggregate(aggregate) if aggregate.partial => {
                EvidenceState::Partial
            }
            _ => EvidenceState::Present,
        }
    };
    let classification = match state {
        EvidenceState::Present => EvidenceClassification::Present,
        EvidenceState::Partial => EvidenceClassification::Partial,
        EvidenceState::Stale => EvidenceClassification::Stale,
        _ => EvidenceClassification::ProviderUnknown,
    };
    let (aggregate, metadata) = match read.payload {
        crate::PendoPayload::Aggregate(aggregate) => (Some(aggregate), None),
        crate::PendoPayload::ReportMetadata(metadata) => (None, Some(metadata)),
    };
    let receipt = read.request.receipt(
        read.response_digest.clone(),
        Some(read.status_code),
        read.response_bytes,
    );
    build_evidence(
        state,
        classification,
        read.request.projection.clone(),
        scope,
        registration,
        read.request.request_digest.clone(),
        receipt,
        aggregate,
        metadata,
        None,
        read.redactions,
        read.provenance,
    )
    .with_provider_digest(provider_digest)
}

fn failure_from_provider(
    scope: &PendoProductUsageScope,
    registration: &PendoRegistration,
    provider_digest: Digest,
    request: &PendoReadRequest,
    provenance: ProviderProvenance,
    error: PendoProviderError,
) -> PendoProductUsageEvidence {
    let kind = error.kind();
    let (state, classification) = match kind {
        ProviderErrorKind::BlockedEnv => (
            EvidenceState::AccessLost,
            EvidenceClassification::BlockedEnv,
        ),
        ProviderErrorKind::Unauthorized | ProviderErrorKind::Forbidden => (
            EvidenceState::AccessLost,
            EvidenceClassification::AccessLost,
        ),
        ProviderErrorKind::RateLimited => (
            EvidenceState::RateLimited,
            EvidenceClassification::RateLimited,
        ),
        _ => (
            EvidenceState::ProviderUnknown,
            EvidenceClassification::ProviderUnknown,
        ),
    };
    let (status_code, response_digest, response_bytes) = error
        .response_metadata()
        .map(|(status, digest, bytes)| (Some(status), digest.clone(), bytes))
        .unwrap_or_else(|| {
            (
                None,
                canonical_digest(&("pendo-provider-error", request.request_digest.clone(), kind)),
                0,
            )
        });
    let receipt = request.receipt(response_digest, status_code, response_bytes);
    build_evidence(
        state,
        classification,
        request.projection.clone(),
        scope,
        registration,
        request.request_digest.clone(),
        receipt,
        None,
        None,
        Some(kind),
        RedactionSummary {
            raw_response_body_dropped: true,
            ..RedactionSummary::default()
        },
        provenance,
    )
    .with_provider_digest(provider_digest)
}

fn failure_evidence(
    scope: &PendoProductUsageScope,
    registration: &PendoRegistration,
    provider_digest: Digest,
    request: &PendoReadRequest,
    provenance: ProviderProvenance,
    state: EvidenceState,
    classification: EvidenceClassification,
    error: ProviderErrorKind,
    status_code: Option<u16>,
    response_digest: Option<Digest>,
    redactions: RedactionSummary,
) -> PendoProductUsageEvidence {
    let receipt = request.receipt(
        response_digest
            .unwrap_or_else(|| canonical_digest(&("pendo-rate-limit", request.digest()))),
        status_code,
        0,
    );
    build_evidence(
        state,
        classification,
        request.projection.clone(),
        scope,
        registration,
        request.request_digest.clone(),
        receipt,
        None,
        None,
        Some(error),
        redactions,
        provenance,
    )
    .with_provider_digest(provider_digest)
}

fn build_evidence(
    state: EvidenceState,
    classification: EvidenceClassification,
    projection: PendoReadProjection,
    scope: &PendoProductUsageScope,
    registration: &PendoRegistration,
    query_digest: Digest,
    read_receipt: PendoReadReceipt,
    aggregate: Option<PendoAggregate>,
    metadata: Option<PendoReportMetadata>,
    error: Option<ProviderErrorKind>,
    redactions: RedactionSummary,
    provenance: ProviderProvenance,
) -> PendoProductUsageEvidence {
    let mut evidence = PendoProductUsageEvidence {
        state,
        classification,
        projection,
        scope_digest: scope.digest(),
        registration_digest: registration.registration_digest().clone(),
        provider_digest: String::new(),
        contract_digest: crate::contract_digest(),
        contract_version: crate::PENDO_PRODUCT_USAGE_RESULT_CONTRACT_VERSION.to_owned(),
        permission_digest: registration.permission_digest().clone(),
        query_digest,
        read_receipt,
        aggregate,
        metadata,
        error,
        redactions,
        provenance,
        read_only: true,
        aggregate_only: true,
        connected: false,
        native_provider: false,
        first_party: false,
        external_writes: false,
        raw_visitor_rows: false,
        raw_pii: false,
        raw_event_payloads: false,
        guide_segment_mutation: false,
        causal_claim: false,
        evidence_digest: String::new(),
    };
    evidence.evidence_digest = evidence.digest();
    evidence
}

trait WithProviderDigest {
    fn with_provider_digest(self, provider_digest: Digest) -> Self;
}

impl WithProviderDigest for PendoProductUsageEvidence {
    fn with_provider_digest(mut self, provider_digest: Digest) -> Self {
        self.provider_digest = provider_digest;
        self.evidence_digest = self.digest();
        self
    }
}

fn recommendation_for(
    scope: &PendoProductUsageScope,
    state: EvidenceState,
    projection: &PendoReadProjection,
) -> PendoUsageRecommendation {
    let disposition = match state {
        EvidenceState::Present => match projection {
            PendoReadProjection::Aggregate {
                metric: AdoptionMetric::PageViews,
            }
            | PendoReadProjection::ReportMetadata {
                target: crate::TargetKind::Page,
            } => RecommendationDisposition::ReviewPageAdoption,
            PendoReadProjection::Aggregate {
                metric: AdoptionMetric::FeatureClicks,
            }
            | PendoReadProjection::ReportMetadata {
                target: crate::TargetKind::Feature,
            } => RecommendationDisposition::ReviewFeatureAdoption,
            PendoReadProjection::Aggregate {
                metric: AdoptionMetric::GuideViews,
            }
            | PendoReadProjection::ReportMetadata {
                target: crate::TargetKind::Guide,
            } => RecommendationDisposition::ReviewGuideAdoption,
            PendoReadProjection::Aggregate { .. } => match scope.target().kind() {
                crate::TargetKind::Page => RecommendationDisposition::ReviewPageAdoption,
                crate::TargetKind::Feature => RecommendationDisposition::ReviewFeatureAdoption,
                crate::TargetKind::Guide => RecommendationDisposition::ReviewGuideAdoption,
            },
        },
        EvidenceState::Partial => RecommendationDisposition::NoRecommendationPartial,
        EvidenceState::Stale => RecommendationDisposition::NoRecommendationStale,
        EvidenceState::AccessLost => RecommendationDisposition::NoRecommendationAccessLost,
        EvidenceState::ProviderUnknown | EvidenceState::Tampered | EvidenceState::Revoked => {
            RecommendationDisposition::NoRecommendationProviderUnknown
        }
        EvidenceState::RateLimited => RecommendationDisposition::NoRecommendationRateLimited,
    };
    let rationale_digest = canonical_digest(&(
        "pendo-product-usage-recommendation/v1",
        scope.target(),
        state,
        &disposition,
    ));
    PendoUsageRecommendation {
        disposition,
        provider_reported_only: true,
        non_mutating: true,
        causal_claim: false,
        outcome_authority: false,
        rationale_digest,
    }
}

pub type PendoServiceError = PendoProductUsageServiceError;
