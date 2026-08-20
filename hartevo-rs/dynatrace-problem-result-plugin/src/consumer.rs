use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    Digest,
    model::{DynatraceProblemEvidence, DynatraceProblemScope, EvidenceState, ModelError},
    provider::DynatraceProblemTransport,
    service::{DynatraceProblemResultService, DynatraceProblemResultServiceError},
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("Mission scope is stale or does not match the provider registration")]
    ScopeMismatch,
    #[error("Mission registration is stale or does not match the provider registration")]
    RegistrationMismatch,
    #[error("provider registration is revoked")]
    Revoked,
    #[error("the same result digest was replayed")]
    ReplayDetected,
    #[error("provider evidence was tampered or failed closed")]
    Tampered,
    #[error("provider evidence is malformed")]
    InvalidEvidence,
}

impl From<DynatraceProblemResultServiceError> for ConsumerError {
    fn from(error: DynatraceProblemResultServiceError) -> Self {
        match error {
            DynatraceProblemResultServiceError::Revoked => Self::Revoked,
            DynatraceProblemResultServiceError::ScopeMismatch
            | DynatraceProblemResultServiceError::InvalidRegistration => Self::RegistrationMismatch,
            DynatraceProblemResultServiceError::InvalidRequest
            | DynatraceProblemResultServiceError::ClockUnavailable => Self::InvalidEvidence,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionDynatraceProblemResult {
    pub consumer_id: String,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub state: EvidenceState,
    pub result_digest: Digest,
    pub problems: Vec<crate::model::ProblemProjection>,
    pub page_count: u8,
    pub page_digests: Vec<Digest>,
    pub partial: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub native_evidence: bool,
    pub truth_authority: bool,
    pub consent_authority: bool,
    pub effect_authority: bool,
    pub receipt_authority: bool,
    pub verification_authority: bool,
    pub outcome_authority: bool,
    pub root_cause_claim: bool,
    pub work_product_adoption: bool,
}

impl MissionDynatraceProblemResult {
    fn from_evidence(evidence: &DynatraceProblemEvidence) -> Self {
        Self {
            consumer_id: crate::DYNATRACE_PROBLEM_RESULT_CONSUMER_ID.to_owned(),
            scope_digest: evidence.scope_digest.clone(),
            registration_digest: evidence.registration_digest.clone(),
            state: evidence.state,
            result_digest: evidence.result_digest.clone(),
            problems: evidence.problems.clone(),
            page_count: evidence.page_count,
            page_digests: evidence.page_digests.clone(),
            partial: evidence.partial,
            connected: false,
            native: false,
            first_party: false,
            native_evidence: false,
            truth_authority: false,
            consent_authority: false,
            effect_authority: false,
            receipt_authority: false,
            verification_authority: false,
            outcome_authority: false,
            root_cause_claim: false,
            work_product_adoption: false,
        }
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.consumer_id != crate::DYNATRACE_PROBLEM_RESULT_CONSUMER_ID
            || self.connected
            || self.native
            || self.first_party
            || self.native_evidence
            || self.truth_authority
            || self.consent_authority
            || self.effect_authority
            || self.receipt_authority
            || self.verification_authority
            || self.outcome_authority
            || self.root_cause_claim
            || self.work_product_adoption
        {
            return Err(ModelError::MalformedProviderResponse);
        }
        Ok(())
    }
}

pub struct MissionDynatraceProblemConsumer {
    scope: DynatraceProblemScope,
    registration_digest: Option<Digest>,
    seen_result_digests: BTreeSet<Digest>,
}

impl fmt::Debug for MissionDynatraceProblemConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionDynatraceProblemConsumer")
            .field("scope_digest", &self.scope.digest())
            .field("registration_digest", &self.registration_digest)
            .field("seen_result_count", &self.seen_result_digests.len())
            .finish()
    }
}

impl MissionDynatraceProblemConsumer {
    pub fn new(scope: DynatraceProblemScope) -> Self {
        Self {
            scope,
            registration_digest: None,
            seen_result_digests: BTreeSet::new(),
        }
    }

    pub fn new_bound(scope: DynatraceProblemScope, registration_digest: Digest) -> Self {
        Self {
            scope,
            registration_digest: Some(registration_digest),
            seen_result_digests: BTreeSet::new(),
        }
    }

    pub fn scope(&self) -> &DynatraceProblemScope {
        &self.scope
    }

    pub fn registration_digest(&self) -> Option<&Digest> {
        self.registration_digest.as_ref()
    }

    pub fn consume<T: DynatraceProblemTransport>(
        &mut self,
        service: &mut DynatraceProblemResultService<T>,
    ) -> Result<MissionDynatraceProblemResult, ConsumerError> {
        let now_ms = service.scope().time_window().to_ms().saturating_sub(1);
        self.consume_at(service, now_ms)
    }

    pub fn consume_at<T: DynatraceProblemTransport>(
        &mut self,
        service: &mut DynatraceProblemResultService<T>,
        at_ms: u64,
    ) -> Result<MissionDynatraceProblemResult, ConsumerError> {
        if self.scope.digest() != service.scope().digest() {
            return Err(ConsumerError::ScopeMismatch);
        }
        if let Some(registration_digest) = &self.registration_digest {
            if registration_digest != &service.registration().registration_digest {
                return Err(ConsumerError::RegistrationMismatch);
            }
        } else {
            self.registration_digest = Some(service.registration().registration_digest.clone());
        }
        let evidence = service.read_at(at_ms).map_err(ConsumerError::from)?;
        evidence.validate().map_err(|_| ConsumerError::Tampered)?;
        if evidence.state == EvidenceState::Tampered || evidence.state == EvidenceState::Revoked {
            return Err(ConsumerError::Tampered);
        }
        if !self
            .seen_result_digests
            .insert(evidence.result_digest.clone())
        {
            return Err(ConsumerError::ReplayDetected);
        }
        Ok(MissionDynatraceProblemResult::from_evidence(&evidence))
    }
}
