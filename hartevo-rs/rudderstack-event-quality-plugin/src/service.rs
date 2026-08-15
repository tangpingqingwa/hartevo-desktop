use thiserror::Error;

use crate::{
    RUDDERSTACK_EVENT_QUALITY_PLUGIN_VERSION_TEXT, RUDDERSTACK_EVENT_QUALITY_SERVICE_ID,
    RUDDERSTACK_EVENT_QUALITY_SERVICE_VERSION_TEXT, canonical_digest, contract_digest,
    model::{
        EvidenceClassification, EvidenceState, ModelError, RecommendationDisposition,
        RegistrationRevocation, RudderStackEventQualityEvidence, RudderStackEventQualityProposal,
        RudderStackEventQualityRecommendation, RudderStackEventQualityScope,
        RudderStackGovernanceMetrics, RudderStackObservationReceipt, RudderStackProviderErrorKind,
        RudderStackReadbackReceipt, RudderStackRegistration, SecretReference, TransportProvenance,
    },
    provider::{
        RudderStackBatchRead, RudderStackOperation, RudderStackOperationFailure,
        RudderStackProvider, RudderStackProviderError, RudderStackTransport,
    },
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RudderStackEventQualityServiceError {
    #[error("RudderStack registration is revoked or invalid")]
    RegistrationRevoked,
    #[error("RudderStack SecretReference is revoked")]
    SecretRevoked,
    #[error("the proposal is a replay")]
    ReplayDetected,
    #[error("the proposal or evidence does not match the current fence")]
    EvidenceMismatch,
    #[error("the provider scope does not match")]
    ScopeMismatch,
    #[error("the provider error is not representable as evidence: {0}")]
    Provider(#[from] RudderStackProviderError),
    #[error("the typed model is invalid: {0}")]
    Model(#[from] ModelError),
}

pub type RudderStackServiceError = RudderStackEventQualityServiceError;

#[derive(Clone, Debug)]
pub struct RudderStackEventQualityServiceDefinition {
    pub id: String,
    pub version: String,
    pub read_only: bool,
    pub proposal_only: bool,
    pub live_execution: bool,
    pub external_writes: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub service_digest: crate::Digest,
}

impl RudderStackEventQualityServiceDefinition {
    pub fn layer1() -> Self {
        let mut value = Self {
            id: RUDDERSTACK_EVENT_QUALITY_SERVICE_ID.to_owned(),
            version: RUDDERSTACK_EVENT_QUALITY_SERVICE_VERSION_TEXT.to_owned(),
            read_only: true,
            proposal_only: true,
            live_execution: false,
            external_writes: false,
            connected: false,
            native: false,
            first_party: false,
            service_digest: crate::Digest::zero(),
        };
        value.service_digest = canonical_digest(&(
            &value.id,
            &value.version,
            value.read_only,
            value.proposal_only,
            value.live_execution,
            value.external_writes,
            value.connected,
            value.native,
            value.first_party,
        ));
        value
    }
}

pub type RudderStackServiceDefinition = RudderStackEventQualityServiceDefinition;

#[derive(Debug)]
pub struct RudderStackEventQualityService<T = crate::BlockedEnvRudderStackTransport>
where
    T: RudderStackTransport,
{
    provider: RudderStackProvider<T>,
    registration: RudderStackRegistration,
    definition: RudderStackEventQualityServiceDefinition,
    last_evidence: Option<RudderStackEventQualityEvidence>,
}

impl<T> RudderStackEventQualityService<T>
where
    T: RudderStackTransport,
{
    pub fn new(
        provider: RudderStackProvider<T>,
    ) -> Result<Self, RudderStackEventQualityServiceError> {
        let registration = RudderStackRegistration::new(
            crate::Digest::from_text(RUDDERSTACK_EVENT_QUALITY_PLUGIN_VERSION_TEXT),
            contract_digest(),
            provider.provider_digest(),
            provider.permissions().digest(),
            provider.scope().digest(),
            provider.scope().privacy_digest(),
            provider.secret_reference().digest(),
        )?;
        Ok(Self {
            provider,
            registration,
            definition: RudderStackEventQualityServiceDefinition::layer1(),
            last_evidence: None,
        })
    }

    pub fn with_registration(
        provider: RudderStackProvider<T>,
        registration: RudderStackRegistration,
    ) -> Result<Self, RudderStackEventQualityServiceError> {
        let service = Self {
            provider,
            registration,
            definition: RudderStackEventQualityServiceDefinition::layer1(),
            last_evidence: None,
        };
        service.ensure_registration()?;
        Ok(service)
    }

    pub fn provider(&self) -> &RudderStackProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut RudderStackProvider<T> {
        &mut self.provider
    }

    pub fn registration(&self) -> &RudderStackRegistration {
        &self.registration
    }

    pub fn definition(&self) -> &RudderStackEventQualityServiceDefinition {
        &self.definition
    }

    pub fn scope(&self) -> &RudderStackEventQualityScope {
        self.provider.scope()
    }

    pub fn secret_reference(&self) -> &SecretReference {
        self.provider.secret_reference()
    }

    pub fn last_evidence(&self) -> Option<&RudderStackEventQualityEvidence> {
        self.last_evidence.as_ref()
    }

    pub fn issue_read_consent(
        &self,
    ) -> Result<RudderStackReadConsent, RudderStackEventQualityServiceError> {
        self.ensure_registration()?;
        Ok(RudderStackReadConsent {
            scope_digest: self.scope().digest(),
            permission_digest: self.scope().permission_digest(),
            mission_digest: self.scope().mission.digest(),
            consent_digest: canonical_digest(&(
                self.scope().digest(),
                self.scope().permission_digest(),
                self.scope().mission.digest(),
            )),
            read_only: true,
            external_writes: false,
        })
    }

    pub fn read(
        &mut self,
    ) -> Result<RudderStackEventQualityEvidence, RudderStackEventQualityServiceError> {
        self.ensure_registration()?;
        let provenance = self.provider.transport().provenance();
        let batch = match self.provider.read_all() {
            Ok(batch) => batch,
            Err(error @ RudderStackProviderError::SecretRevoked) => return Err(error.into()),
            Err(error @ RudderStackProviderError::RegistrationRevoked) => return Err(error.into()),
            Err(error) => singleton_failure_batch(&error),
        };
        let evidence = self.normalize_batch(&batch, provenance)?;
        self.registration
            .bind_evidence(evidence.evidence_digest.clone())?;
        let mut evidence = evidence;
        evidence.registration_digest = self.registration.registration_digest.clone();
        self.last_evidence = Some(evidence.clone());
        Ok(evidence)
    }

    pub fn compile_proposal(
        &mut self,
    ) -> Result<RudderStackEventQualityProposal, RudderStackEventQualityServiceError> {
        let evidence = self.read()?;
        self.compile_proposal_from_evidence(evidence)
    }

    pub fn compile_proposal_from_evidence(
        &self,
        evidence: RudderStackEventQualityEvidence,
    ) -> Result<RudderStackEventQualityProposal, RudderStackEventQualityServiceError> {
        self.ensure_registration()?;
        self.verify_evidence(&evidence)?;
        let recommendation = recommendation_for(self.scope(), &evidence);
        let mut proposal = RudderStackEventQualityProposal {
            scope: self.scope().clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            registration_digest: self.registration.registration_digest.clone(),
            provider_digest: self.provider.provider_digest(),
            contract_digest: contract_digest(),
            permission_digest: self.scope().permission_digest(),
            proposal_only: true,
            connected: false,
            native: false,
            first_party: false,
            adopts_work_product: false,
            adopts_outcome: false,
            truth_authority: false,
            evidence,
            recommendation,
            proposal_digest: crate::Digest::zero(),
        };
        proposal.proposal_digest = proposal.digest();
        Ok(proposal)
    }

    pub fn verify_proposal(
        &self,
        proposal: &RudderStackEventQualityProposal,
    ) -> Result<(), RudderStackEventQualityServiceError> {
        self.ensure_registration()?;
        if proposal.scope != *self.scope()
            || proposal.registration_digest != self.registration.registration_digest
            || proposal.provider_digest != self.provider.provider_digest()
            || proposal.contract_digest != contract_digest()
            || proposal.permission_digest != self.scope().permission_digest()
            || proposal.proposal_digest != proposal.digest()
            || proposal.evidence_digest != proposal.evidence.evidence_digest
            || proposal.evidence.registration_digest != self.registration.registration_digest
        {
            return Err(RudderStackEventQualityServiceError::EvidenceMismatch);
        }
        self.verify_evidence(&proposal.evidence)
    }

    pub fn verify(
        &self,
        proposal: &RudderStackEventQualityProposal,
    ) -> Result<crate::RudderStackVerificationReceipt, RudderStackEventQualityServiceError> {
        self.verify_proposal(proposal)?;
        Ok(crate::RudderStackVerificationReceipt::new(proposal))
    }

    pub fn record_observation(
        &self,
        proposal: &RudderStackEventQualityProposal,
    ) -> Result<RudderStackObservationReceipt, RudderStackEventQualityServiceError> {
        self.verify_proposal(proposal)?;
        Ok(RudderStackObservationReceipt::new(proposal))
    }

    pub fn record(
        &self,
        proposal: &RudderStackEventQualityProposal,
    ) -> Result<RudderStackObservationReceipt, RudderStackEventQualityServiceError> {
        self.record_observation(proposal)
    }

    pub fn read_back(
        &self,
        proposal: &RudderStackEventQualityProposal,
    ) -> Result<RudderStackReadbackReceipt, RudderStackEventQualityServiceError> {
        self.verify_proposal(proposal)?;
        Ok(RudderStackReadbackReceipt {
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence_digest.clone(),
            status: "verified_against_typed_proposal_only".to_owned(),
            independent_native_readback: false,
            connected: false,
            native: false,
            first_party: false,
        })
    }

    pub fn revoke_registration(
        &mut self,
    ) -> Result<RegistrationRevocation, RudderStackEventQualityServiceError> {
        Ok(self.registration.revoke()?)
    }

    pub fn restore_registration(
        &mut self,
    ) -> Result<RegistrationRevocation, RudderStackEventQualityServiceError> {
        Ok(self.registration.restore()?)
    }

    pub fn revoke(
        &mut self,
    ) -> Result<RegistrationRevocation, RudderStackEventQualityServiceError> {
        self.revoke_registration()
    }

    pub fn restore(
        &mut self,
    ) -> Result<RegistrationRevocation, RudderStackEventQualityServiceError> {
        self.restore_registration()
    }

    pub fn revoke_secret(&mut self) -> Result<(), RudderStackEventQualityServiceError> {
        self.provider.secret_reference_mut().revoke()?;
        Ok(())
    }

    fn ensure_registration(&self) -> Result<(), RudderStackEventQualityServiceError> {
        if !self.registration.is_active() {
            return Err(RudderStackEventQualityServiceError::RegistrationRevoked);
        }
        self.registration
            .validate()
            .map_err(|_| RudderStackEventQualityServiceError::RegistrationRevoked)?;
        if self.provider.secret_reference().is_revoked() {
            return Err(RudderStackEventQualityServiceError::SecretRevoked);
        }
        if self.registration.scope_digest != self.scope().digest()
            || self.registration.permission_digest != self.scope().permission_digest()
            || self.registration.privacy_digest != self.scope().privacy_digest()
            || self.registration.provider_digest != self.provider.provider_digest()
            || self.registration.secret_reference_digest
                != self.provider.secret_reference().digest()
        {
            return Err(RudderStackEventQualityServiceError::RegistrationRevoked);
        }
        Ok(())
    }

    fn normalize_batch(
        &self,
        batch: &RudderStackBatchRead,
        provenance: TransportProvenance,
    ) -> Result<RudderStackEventQualityEvidence, RudderStackEventQualityServiceError> {
        let mut source_metadata = None;
        let mut tracking_plan_versions = Vec::new();
        let mut violations = Vec::new();
        let mut delivery_health = Vec::new();
        let mut governance_metrics: Option<RudderStackGovernanceMetrics> = None;
        let mut stale = false;
        let mut partial = false;
        let mut empty_responses = 0_u16;

        for read in &batch.reads {
            partial |= read.response.status_code == 206
                || read
                    .response
                    .cursor_receipt
                    .as_ref()
                    .is_some_and(|cursor| cursor.has_more);
            if read.response.is_empty() {
                empty_responses = empty_responses.saturating_add(1);
            }
            match read.operation {
                RudderStackOperation::SourceMetadataRead => {
                    if let Some(value) = &read.response.source_metadata {
                        if value.source != self.scope().source.id
                            || value.revision != self.scope().source.revision
                        {
                            stale = true;
                        } else {
                            source_metadata = Some(value.clone());
                        }
                    }
                }
                RudderStackOperation::TrackingPlanVersionsRead => {
                    for value in &read.response.tracking_plan_versions {
                        if self.scope().tracking_plan.as_ref().is_none_or(|plan| {
                            value.tracking_plan == plan.id && value.revision == plan.revision
                        }) {
                            tracking_plan_versions.push(value.clone());
                        } else {
                            stale = true;
                        }
                    }
                }
                RudderStackOperation::SchemaViolationsRead => {
                    for value in &read.response.violations {
                        if !self.scope().violation.contains(value.violation_kind) {
                            stale = true;
                        } else {
                            violations.push(value.clone());
                        }
                    }
                }
                RudderStackOperation::DeliveryHealthRead => {
                    for value in &read.response.delivery_health {
                        if self.scope().destination.as_ref().is_none_or(|destination| {
                            value.destination == destination.id
                                && value.revision == destination.revision
                        }) {
                            delivery_health.push(value.clone());
                        } else {
                            stale = true;
                        }
                    }
                }
                RudderStackOperation::GovernanceMetricsRead => {
                    if let Some(value) = &read.response.governance_metrics {
                        if value.window != self.scope().window {
                            stale = true;
                        } else {
                            governance_metrics = Some(value.clone());
                        }
                    }
                }
            }
        }

        let highest_failure = batch
            .failures
            .iter()
            .map(|failure| failure.kind)
            .max_by_key(|kind| failure_priority(*kind));
        let has_data = source_metadata.is_some()
            || !tracking_plan_versions.is_empty()
            || !violations.is_empty()
            || !delivery_health.is_empty()
            || governance_metrics.is_some();
        let (state, classification) = if stale {
            (EvidenceState::Stale, EvidenceClassification::Stale)
        } else if let Some(kind) = highest_failure {
            if has_data {
                (EvidenceState::Partial, EvidenceClassification::Partial)
            } else {
                state_for_failure(kind, provenance)
            }
        } else if !has_data && partial {
            (EvidenceState::Partial, EvidenceClassification::Partial)
        } else if !has_data {
            (EvidenceState::Empty, EvidenceClassification::Empty)
        } else if partial {
            (EvidenceState::Partial, EvidenceClassification::Partial)
        } else {
            (EvidenceState::Complete, EvidenceClassification::Normalized)
        };
        let page_count = batch.page_count.saturating_add(empty_responses);
        let evidence = RudderStackEventQualityEvidence::from_parts(
            state,
            classification,
            provenance,
            source_metadata,
            tracking_plan_versions,
            violations,
            delivery_health,
            governance_metrics,
            batch.cursor_receipts(),
            batch.rate_limit_receipts(),
            batch.response_digests(),
            self.scope(),
            self.provider.provider_digest(),
            self.registration.registration_digest.clone(),
            page_count,
            batch.complete_pagination,
        );
        Ok(evidence)
    }

    fn verify_evidence(
        &self,
        evidence: &RudderStackEventQualityEvidence,
    ) -> Result<(), RudderStackEventQualityServiceError> {
        if evidence.validate_digest().is_err()
            || evidence.scope_digest != self.scope().digest()
            || evidence.permission_digest != self.scope().permission_digest()
            || evidence.privacy_digest != self.scope().privacy_digest()
            || evidence.provider_digest != self.provider.provider_digest()
            || evidence.registration_digest != self.registration.registration_digest
            || evidence.digests.contract_digest != contract_digest()
            || evidence.digests.plugin_version_digest
                != crate::Digest::from_text(RUDDERSTACK_EVENT_QUALITY_PLUGIN_VERSION_TEXT)
            || evidence.digests.provider_digest != self.provider.provider_digest()
            || evidence.digests.permission_digest != self.scope().permission_digest()
            || evidence.digests.scope_digest != self.scope().digest()
            || evidence.digests.privacy_digest != self.scope().privacy_digest()
        {
            return Err(RudderStackEventQualityServiceError::EvidenceMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RudderStackReadConsent {
    pub scope_digest: crate::Digest,
    pub permission_digest: crate::Digest,
    pub mission_digest: crate::Digest,
    pub consent_digest: crate::Digest,
    pub read_only: bool,
    pub external_writes: bool,
}

fn singleton_failure_batch(error: &RudderStackProviderError) -> RudderStackBatchRead {
    RudderStackBatchRead {
        reads: Vec::new(),
        failures: vec![RudderStackOperationFailure {
            operation: error.operation(),
            request_digest: None,
            kind: error.kind(),
            response_digest: error.response_digest(),
            rate_limit: error.rate_limit(),
        }],
        page_count: 0,
        complete_pagination: false,
    }
}

fn failure_priority(kind: RudderStackProviderErrorKind) -> u8 {
    match kind {
        RudderStackProviderErrorKind::Tamper => 100,
        RudderStackProviderErrorKind::Stale => 90,
        RudderStackProviderErrorKind::AccessLost => 80,
        RudderStackProviderErrorKind::BlockedEnv => 79,
        RudderStackProviderErrorKind::RateLimited => 70,
        RudderStackProviderErrorKind::PermissionDenied => 65,
        RudderStackProviderErrorKind::ResponseTooLarge => 60,
        RudderStackProviderErrorKind::MalformedResponse => 55,
        RudderStackProviderErrorKind::ProviderUnknown => 50,
    }
}

fn state_for_failure(
    kind: RudderStackProviderErrorKind,
    provenance: TransportProvenance,
) -> (EvidenceState, EvidenceClassification) {
    match kind {
        RudderStackProviderErrorKind::Tamper => {
            (EvidenceState::Tamper, EvidenceClassification::Tamper)
        }
        RudderStackProviderErrorKind::Stale => {
            (EvidenceState::Stale, EvidenceClassification::Stale)
        }
        RudderStackProviderErrorKind::RateLimited => (
            EvidenceState::RateLimited,
            EvidenceClassification::RateLimited,
        ),
        RudderStackProviderErrorKind::AccessLost
        | RudderStackProviderErrorKind::PermissionDenied => (
            EvidenceState::AccessLost,
            EvidenceClassification::AccessLost,
        ),
        RudderStackProviderErrorKind::BlockedEnv => (
            EvidenceState::AccessLost,
            if provenance.is_blocked_env() {
                EvidenceClassification::BlockedEnv
            } else {
                EvidenceClassification::AccessLost
            },
        ),
        RudderStackProviderErrorKind::ResponseTooLarge
        | RudderStackProviderErrorKind::MalformedResponse
        | RudderStackProviderErrorKind::ProviderUnknown => (
            EvidenceState::ProviderUnknown,
            EvidenceClassification::ProviderUnknown,
        ),
    }
}

fn recommendation_for(
    scope: &RudderStackEventQualityScope,
    evidence: &RudderStackEventQualityEvidence,
) -> RudderStackEventQualityRecommendation {
    let disposition = match evidence.state {
        EvidenceState::Complete => {
            if !evidence.violations.is_empty() {
                RecommendationDisposition::ReviewSchemaViolations
            } else if !evidence.delivery_health.is_empty() {
                RecommendationDisposition::ReviewDeliveryHealth
            } else {
                RecommendationDisposition::ReviewTrackingPlanCompliance
            }
        }
        EvidenceState::Partial => RecommendationDisposition::NoRecommendationPartial,
        EvidenceState::Empty => RecommendationDisposition::NoRecommendationEmpty,
        EvidenceState::RateLimited => RecommendationDisposition::NoRecommendationRateLimited,
        EvidenceState::AccessLost => RecommendationDisposition::NoRecommendationAccessLost,
        EvidenceState::ProviderUnknown => {
            RecommendationDisposition::NoRecommendationProviderUnknown
        }
        EvidenceState::Tamper => RecommendationDisposition::NoRecommendationTamper,
        EvidenceState::Stale => RecommendationDisposition::NoRecommendationStale,
        EvidenceState::Revoked => RecommendationDisposition::NoRecommendationRevoked,
    };
    let rationale_digest = canonical_digest(&(
        "rudderstack-event-quality-recommendation/v1",
        &scope.digest(),
        evidence.state,
        &evidence.evidence_digest,
        disposition,
    ));
    RudderStackEventQualityRecommendation {
        disposition,
        provider_reported_only: true,
        non_mutating: true,
        claims_event_quality: false,
        claims_schema_truth: false,
        claims_delivery_success: false,
        claims_business_success: false,
        rationale_digest,
    }
}
