//! Typed Amplitude experiment-result service and proposal/read-back seam.

use std::cmp::Ordering;

use chrono::Utc;

use crate::{
    AmplitudeEffectIntent, AmplitudeEffectReceipt, AmplitudeEffectReceiptStatus,
    AmplitudeExperimentResultProposal, AmplitudeExperimentResultRead, AmplitudeExperimentScope,
    AmplitudeReadConsent, AmplitudeReadbackReceipt, AmplitudeRegistration, AmplitudeResultError,
    AmplitudeResultEvidence, AmplitudeResultProjection, AmplitudeResultState,
    AmplitudeTransportError, DecisionMetadata, EvidenceClassification, FreshnessReceipt,
    MetricDirection, ReadReceipt, ReadbackStatus, RecordingReceipt, ResponseReceipt,
    ResultRecommendation, ResultRecommendationDisposition, TransportProvenance, TransportStatus,
    VariantBinding, canonical_digest,
};
use crate::{AmplitudeProvider, AmplitudeTransport};

#[derive(Debug)]
pub struct AmplitudeExperimentResultService<T: AmplitudeTransport> {
    provider: AmplitudeProvider<T>,
}

impl<T: AmplitudeTransport> AmplitudeExperimentResultService<T> {
    pub fn new(provider: AmplitudeProvider<T>) -> Result<Self, AmplitudeResultError> {
        provider.registration().validate(provider.scope())?;
        Ok(Self { provider })
    }

    #[must_use]
    pub fn from_provider(provider: AmplitudeProvider<T>) -> Self {
        Self { provider }
    }

    #[must_use]
    pub fn provider(&self) -> &AmplitudeProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut AmplitudeProvider<T> {
        &mut self.provider
    }

    #[must_use]
    pub fn scope(&self) -> &AmplitudeExperimentScope {
        self.provider.scope()
    }

    #[must_use]
    pub fn registration(&self) -> &AmplitudeRegistration {
        self.provider.registration()
    }

    /// Issue a typed Layer-1 consent envelope. This is a host-consent seam,
    /// not proof that a native user consent dialog or credential flow ran.
    #[must_use]
    pub fn issue_read_consent(&self) -> AmplitudeReadConsent {
        AmplitudeReadConsent::for_scope(self.scope())
    }

    pub fn read_experiment_result(
        &mut self,
        operation: AmplitudeExperimentResultRead,
    ) -> Result<AmplitudeResultEvidence, AmplitudeResultError> {
        let consent = self.issue_read_consent();
        self.read_with_consent(operation, &consent)
    }

    pub fn read_with_consent(
        &mut self,
        operation: AmplitudeExperimentResultRead,
        consent: &AmplitudeReadConsent,
    ) -> Result<AmplitudeResultEvidence, AmplitudeResultError> {
        consent.validate(self.scope())?;
        let intent = AmplitudeEffectIntent::for_read(self.scope(), consent, &operation);
        match self.provider.read_result_page(&operation) {
            Ok(read) => normalize_read(self.scope(), operation, intent, read),
            Err(AmplitudeResultError::Transport(error)) => {
                Ok(error_evidence(self.scope(), operation, intent, error))
            }
            Err(error) => Err(error),
        }
    }

    pub fn compile_experiment_result_proposal(
        &mut self,
        operation: AmplitudeExperimentResultRead,
    ) -> Result<AmplitudeExperimentResultProposal, AmplitudeResultError> {
        let evidence = self.read_experiment_result(operation)?;
        self.compile_proposal_from_evidence(evidence)
    }

    pub fn compile_proposal_with_consent(
        &mut self,
        operation: AmplitudeExperimentResultRead,
        consent: &AmplitudeReadConsent,
    ) -> Result<AmplitudeExperimentResultProposal, AmplitudeResultError> {
        let evidence = self.read_with_consent(operation, consent)?;
        self.compile_proposal_from_evidence(evidence)
    }

    pub fn compile_proposal_from_evidence(
        &self,
        evidence: AmplitudeResultEvidence,
    ) -> Result<AmplitudeExperimentResultProposal, AmplitudeResultError> {
        self.registration().validate(self.scope())?;
        if evidence.scope_digest != self.scope().digest()
            || evidence.revision_digest != self.scope().revision_digest()
            || evidence.native
            || evidence.connected
        {
            return Err(AmplitudeResultError::EvidenceMismatch);
        }
        let recommendation = recommendation_for(self.scope(), &evidence);
        let source_evidence_digest = evidence.digest();
        Ok(AmplitudeExperimentResultProposal {
            scope_digest: self.scope().digest(),
            revision_digest: self.scope().revision_digest(),
            registration_digest: self.registration().registration_digest.clone(),
            project: self.scope().project().clone(),
            experiment: self.scope().experiment().clone(),
            mission: self.scope().mission().clone(),
            work_product: self.scope().work_product().clone(),
            evidence,
            source_evidence_digest,
            recommendation,
            proposal_only: true,
            connected: false,
            native: false,
            adopts_outcome: false,
        })
    }

    /// Record an in-memory observation receipt. Layer 1 never persists a
    /// kernel receipt and never executes a mutating provider effect.
    pub fn record_experiment_result_observation(
        &self,
        proposal: &AmplitudeExperimentResultProposal,
    ) -> Result<AmplitudeEffectReceipt, AmplitudeResultError> {
        self.verify_proposal(proposal)?;
        Ok(proposal.evidence.effect_receipt.clone())
    }

    /// Verify the proposal and its normalized evidence without a second native
    /// provider call. This is the host-owned read-back seam for Layer 1.
    pub fn read_back_experiment_result(
        &self,
        proposal: &AmplitudeExperimentResultProposal,
    ) -> Result<AmplitudeReadbackReceipt, AmplitudeResultError> {
        self.verify_proposal(proposal)?;
        Ok(AmplitudeReadbackReceipt {
            proposal_digest: proposal.digest(),
            evidence_digest: proposal.evidence.digest(),
            scope_digest: self.scope().digest(),
            revision_digest: self.scope().revision_digest(),
            status: ReadbackStatus::VerifiedAgainstProposal,
            native: false,
            connected: false,
        })
    }

    pub fn verify_proposal(
        &self,
        proposal: &AmplitudeExperimentResultProposal,
    ) -> Result<(), AmplitudeResultError> {
        self.registration().validate(self.scope())?;
        if !proposal.proposal_only
            || proposal.connected
            || proposal.native
            || proposal.adopts_outcome
            || proposal.scope_digest != self.scope().digest()
            || proposal.revision_digest != self.scope().revision_digest()
            || proposal.registration_digest != self.registration().registration_digest
            || proposal.project != *self.scope().project()
            || proposal.experiment != *self.scope().experiment()
            || proposal.mission != *self.scope().mission()
            || proposal.work_product != *self.scope().work_product()
            || proposal.evidence.scope_digest != self.scope().digest()
            || proposal.evidence.revision_digest != self.scope().revision_digest()
            || proposal.evidence.native
            || proposal.evidence.connected
            || proposal.source_evidence_digest != proposal.evidence.digest()
        {
            return Err(AmplitudeResultError::EvidenceMismatch);
        }
        Ok(())
    }

    pub fn revoke(
        &mut self,
        reason: impl Into<String>,
    ) -> Result<crate::RegistrationRevocationReceipt, AmplitudeResultError> {
        self.provider.revoke(reason)
    }

    pub fn restore(&mut self) -> Result<(), AmplitudeResultError> {
        self.provider.restore()
    }
}

fn normalize_read(
    scope: &AmplitudeExperimentScope,
    operation: AmplitudeExperimentResultRead,
    intent: AmplitudeEffectIntent,
    read: crate::provider::AmplitudeProviderRead,
) -> Result<AmplitudeResultEvidence, AmplitudeResultError> {
    let page = read.page;
    let projection = AmplitudeResultProjection {
        project: scope.project().clone(),
        experiment: scope.experiment().clone(),
        segment: scope.segment().clone(),
        exposure_window: scope.exposure_window().clone(),
        metric: scope.metric().clone(),
        variants: page
            .variants
            .iter()
            .map(|variant| {
                let metric = &variant.metrics[0];
                Ok(crate::AmplitudeVariantResult {
                    variant: VariantBinding::new(
                        variant.variant_id.clone(),
                        variant.variant_revision,
                    )?,
                    exposure_count: variant.exposure_count,
                    metric: crate::AmplitudeMetricResult {
                        metric: scope.metric().clone(),
                        value: metric.value,
                        confidence: metric.confidence.clone(),
                        decision: DecisionMetadata {
                            provider_decision: metric.decision,
                            provider_reported: true,
                        },
                    },
                })
            })
            .collect::<Result<Vec<_>, AmplitudeResultError>>()?,
        provider_decision: page.decision,
        partial: page.partial,
    };
    let freshness = freshness_receipt(
        page.generated_at,
        read.observed_at,
        operation.max_age_seconds(),
    );
    let state = state_for(scope, &projection, freshness.fresh);
    let classification = if state == AmplitudeResultState::ProviderUnknown {
        EvidenceClassification::ProviderUnknown
    } else {
        EvidenceClassification::Normalized
    };
    let request_digest = read.request.digest();
    let request_id = canonical_digest(&(request_digest.clone(), read.response_digest.clone()));
    let read_receipt = ReadReceipt {
        request_id,
        request_digest,
        endpoint: read.request.path.clone(),
        page: read.request.page,
        page_size: read.request.page_size,
        max_response_bytes: crate::MAX_RESPONSE_BYTES,
        cost_units: read.cost_units,
        response_bytes: read.response_bytes,
        provider_request_id: read.provider_request_id.clone(),
        transport_status: TransportStatus::Ok,
    };
    let response_receipt = ResponseReceipt {
        response_digest: read.response_digest.clone(),
        response_bytes: read.response_bytes,
        provider_request_id: read.provider_request_id,
    };
    let recording = RecordingReceipt::new(read.provenance, &response_receipt.response_digest);
    let effect_receipt = AmplitudeEffectReceipt {
        intent_digest: intent.digest(),
        status: AmplitudeEffectReceiptStatus::ObservationRecorded,
        provider_receipt_digest: response_receipt.response_digest.clone(),
        native: false,
        connected: false,
        durable: false,
    };
    Ok(AmplitudeResultEvidence {
        scope_digest: scope.digest(),
        revision_digest: scope.revision_digest(),
        operation,
        projection: Some(projection),
        state,
        classification,
        read_receipt,
        response_receipt: Some(response_receipt),
        freshness: Some(freshness),
        recording,
        effect_receipt,
        native: false,
        connected: false,
    })
}

fn error_evidence(
    scope: &AmplitudeExperimentScope,
    operation: AmplitudeExperimentResultRead,
    intent: AmplitudeEffectIntent,
    error: AmplitudeTransportError,
) -> AmplitudeResultEvidence {
    let provenance = if matches!(error, AmplitudeTransportError::BlockedEnv) {
        TransportProvenance::BlockedEnv
    } else {
        TransportProvenance::Recording
    };
    let transport_status = transport_status(&error);
    let state = match error {
        AmplitudeTransportError::BlockedEnv
        | AmplitudeTransportError::AccessDenied { .. }
        | AmplitudeTransportError::NotFound => AmplitudeResultState::AccessLost,
        AmplitudeTransportError::RateLimited
        | AmplitudeTransportError::ProviderError { .. }
        | AmplitudeTransportError::Timeout
        | AmplitudeTransportError::InvalidDiagnostic => AmplitudeResultState::ProviderUnknown,
    };
    let classification = if matches!(provenance, TransportProvenance::BlockedEnv) {
        EvidenceClassification::BlockedEnv
    } else if state == AmplitudeResultState::ProviderUnknown {
        EvidenceClassification::ProviderUnknown
    } else {
        EvidenceClassification::AccessLost
    };
    let request_digest = canonical_digest(&(scope.digest(), operation.digest()));
    let response_digest = canonical_digest(&(transport_status, request_digest.clone()));
    let endpoint = format!("/api/3/chart/{}/csv", operation.chart_id());
    let read_receipt = ReadReceipt {
        request_id: canonical_digest(&(request_digest.clone(), response_digest.clone())),
        request_digest,
        endpoint,
        page: operation.page(),
        page_size: operation.page_size(),
        max_response_bytes: crate::MAX_RESPONSE_BYTES,
        cost_units: 0,
        response_bytes: 0,
        provider_request_id: None,
        transport_status,
    };
    let recording = RecordingReceipt::new(provenance, &response_digest);
    let effect_receipt = AmplitudeEffectReceipt {
        intent_digest: intent.digest(),
        status: AmplitudeEffectReceiptStatus::NotExecutedLayer1,
        provider_receipt_digest: response_digest,
        native: false,
        connected: false,
        durable: false,
    };
    AmplitudeResultEvidence {
        scope_digest: scope.digest(),
        revision_digest: scope.revision_digest(),
        operation,
        projection: None,
        state,
        classification,
        read_receipt,
        response_receipt: None,
        freshness: None,
        recording,
        effect_receipt,
        native: false,
        connected: false,
    }
}

fn freshness_receipt(
    source_generated_at: chrono::DateTime<Utc>,
    observed_at: chrono::DateTime<Utc>,
    max_age_seconds: u32,
) -> FreshnessReceipt {
    let age_seconds = if observed_at > source_generated_at {
        (observed_at - source_generated_at).num_seconds().max(0) as u64
    } else {
        0
    };
    FreshnessReceipt {
        source_generated_at,
        observed_at,
        max_age_seconds,
        age_seconds,
        fresh: age_seconds <= u64::from(max_age_seconds),
    }
}

fn state_for(
    scope: &AmplitudeExperimentScope,
    projection: &AmplitudeResultProjection,
    fresh: bool,
) -> AmplitudeResultState {
    if projection.variants.is_empty() {
        AmplitudeResultState::Empty
    } else if !fresh {
        AmplitudeResultState::Stale
    } else if projection.partial {
        AmplitudeResultState::Partial
    } else if projection
        .variants
        .iter()
        .any(|variant| variant.exposure_count < scope.metric().minimum_exposure())
    {
        AmplitudeResultState::InsufficientExposure
    } else {
        match projection.provider_decision {
            crate::ProviderDecisionState::Significant => AmplitudeResultState::Significant,
            crate::ProviderDecisionState::Inconclusive => AmplitudeResultState::Inconclusive,
            crate::ProviderDecisionState::Unknown => AmplitudeResultState::ProviderUnknown,
        }
    }
}

fn recommendation_for(
    scope: &AmplitudeExperimentScope,
    evidence: &AmplitudeResultEvidence,
) -> ResultRecommendation {
    let disposition = match evidence.state {
        AmplitudeResultState::Significant => {
            ResultRecommendationDisposition::ProviderReportedSignificant
        }
        AmplitudeResultState::Inconclusive => {
            ResultRecommendationDisposition::NoRecommendationInconclusive
        }
        AmplitudeResultState::InsufficientExposure => {
            ResultRecommendationDisposition::NoRecommendationInsufficientExposure
        }
        AmplitudeResultState::Stale => ResultRecommendationDisposition::NoRecommendationStale,
        AmplitudeResultState::Partial => ResultRecommendationDisposition::NoRecommendationPartial,
        AmplitudeResultState::Empty => ResultRecommendationDisposition::NoRecommendationEmpty,
        AmplitudeResultState::AccessLost => {
            ResultRecommendationDisposition::NoRecommendationAccessLost
        }
        AmplitudeResultState::ProviderUnknown => {
            ResultRecommendationDisposition::NoRecommendationProviderUnknown
        }
    };
    let recommended_variant = if evidence.state == AmplitudeResultState::Significant {
        evidence.projection.as_ref().and_then(|projection| {
            projection
                .variants
                .iter()
                .filter_map(|variant| variant.metric.value.map(|value| (variant, value)))
                .max_by(|(_, left), (_, right)| match scope.metric().direction() {
                    MetricDirection::Increase => left.partial_cmp(right).unwrap_or(Ordering::Equal),
                    MetricDirection::Decrease => right.partial_cmp(left).unwrap_or(Ordering::Equal),
                })
                .map(|(variant, _)| variant.variant.clone())
        })
    } else {
        None
    };
    ResultRecommendation {
        disposition,
        recommended_variant,
        provider_reported_only: true,
        statistical_claim: false,
    }
}

fn transport_status(error: &AmplitudeTransportError) -> TransportStatus {
    match error {
        AmplitudeTransportError::BlockedEnv => TransportStatus::BlockedEnv,
        AmplitudeTransportError::AccessDenied { .. } => TransportStatus::AccessDenied,
        AmplitudeTransportError::NotFound => TransportStatus::NotFound,
        AmplitudeTransportError::RateLimited => TransportStatus::RateLimited,
        AmplitudeTransportError::ProviderError { .. } => TransportStatus::ProviderError,
        AmplitudeTransportError::Timeout => TransportStatus::Timeout,
        AmplitudeTransportError::InvalidDiagnostic => TransportStatus::ProviderError,
    }
}
