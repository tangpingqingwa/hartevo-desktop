use serde::{Deserialize, Serialize};

use crate::{
    canonical_digest,
    model::{
        Digest, EvaluationReceiptCandidate, EvaluationResultProposal, LangSmithEvaluationError,
        LangSmithEvaluationReadRequest, LangSmithEvaluationScope, MissionId, Revision,
    },
    service::LangSmithEvaluationService,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MissionEvaluationRequest {
    pub mission_id: MissionId,
    pub mission_revision: Revision,
    pub scope_digest: Digest,
    pub evaluation: LangSmithEvaluationReadRequest,
    pub decision_revision: Revision,
    pub request_digest: Digest,
}

impl MissionEvaluationRequest {
    #[allow(clippy::needless_pass_by_value)]
    pub fn new(
        scope: LangSmithEvaluationScope,
        page_size: u16,
        as_of_ms: u64,
        decision_revision: Revision,
    ) -> Result<Self, LangSmithEvaluationError> {
        let evaluation = LangSmithEvaluationReadRequest::new(scope.clone(), page_size, as_of_ms)?;
        decision_revision.validate("mission_decision_revision")?;
        let mut request = Self {
            mission_id: scope.mission.clone(),
            mission_revision: scope.mission_revision.clone(),
            scope_digest: scope.digest().clone(),
            evaluation,
            decision_revision,
            request_digest: Digest::from_text("uninitialized-mission-request"),
        };
        request.request_digest = canonical_digest(&MissionRequestIdentity {
            mission_id: request.mission_id.clone(),
            mission_revision: request.mission_revision.clone(),
            scope_digest: request.scope_digest.clone(),
            evaluation: request.evaluation.clone(),
            decision_revision: request.decision_revision.clone(),
        });
        Ok(request)
    }

    pub fn fixture(scope: LangSmithEvaluationScope) -> Result<Self, LangSmithEvaluationError> {
        Self::new(scope, 25, 10_000, Revision::fixture())
    }

    pub fn validate(&self) -> Result<(), LangSmithEvaluationError> {
        self.mission_id.validate()?;
        self.mission_revision.validate("mission_revision")?;
        self.scope_digest.validate("mission_scope_digest")?;
        self.evaluation
            .scope
            .validate()
            .map_err(|_| LangSmithEvaluationError::MissionMismatch)?;
        self.decision_revision
            .validate("mission_decision_revision")?;
        if self.mission_id != self.evaluation.scope.mission
            || self.mission_revision != self.evaluation.scope.mission_revision
            || self.scope_digest != *self.evaluation.scope.digest()
        {
            return Err(LangSmithEvaluationError::MissionMismatch);
        }
        self.request_digest.validate("mission_request_digest")?;
        let expected = canonical_digest(&MissionRequestIdentity {
            mission_id: self.mission_id.clone(),
            mission_revision: self.mission_revision.clone(),
            scope_digest: self.scope_digest.clone(),
            evaluation: self.evaluation.clone(),
            decision_revision: self.decision_revision.clone(),
        });
        if self.request_digest != expected {
            return Err(LangSmithEvaluationError::ProposalTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct MissionRequestIdentity {
    mission_id: MissionId,
    mission_revision: Revision,
    scope_digest: Digest,
    evaluation: LangSmithEvaluationReadRequest,
    decision_revision: Revision,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct MissionEvaluationResult {
    pub consumer_id: String,
    pub mission_id: MissionId,
    pub mission_revision: Revision,
    pub scope_digest: Digest,
    pub proposal: EvaluationResultProposal,
    pub receipt_candidate: EvaluationReceiptCandidate,
    pub adopted: bool,
    pub durable: bool,
    pub result_digest: Digest,
}

impl MissionEvaluationResult {
    fn new(
        request: &MissionEvaluationRequest,
        proposal: EvaluationResultProposal,
        receipt_candidate: EvaluationReceiptCandidate,
    ) -> Self {
        let mut result = Self {
            consumer_id: String::from(crate::LANGSMITH_EVALUATION_CONSUMER_ID),
            mission_id: request.mission_id.clone(),
            mission_revision: request.mission_revision.clone(),
            scope_digest: request.scope_digest.clone(),
            proposal,
            receipt_candidate,
            adopted: false,
            durable: false,
            result_digest: Digest::from_text("uninitialized-mission-result"),
        };
        result.result_digest = canonical_digest(&MissionResultIdentity {
            consumer_id: result.consumer_id.clone(),
            mission_id: result.mission_id.clone(),
            mission_revision: result.mission_revision.clone(),
            scope_digest: result.scope_digest.clone(),
            proposal: result.proposal.clone(),
            receipt_candidate: result.receipt_candidate.clone(),
            adopted: result.adopted,
            durable: result.durable,
        });
        result
    }

    pub fn validate(&self) -> Result<(), LangSmithEvaluationError> {
        self.mission_id.validate()?;
        self.mission_revision.validate("mission_revision")?;
        self.scope_digest.validate("mission_scope_digest")?;
        self.proposal.scope.validate()?;
        if self.consumer_id != crate::LANGSMITH_EVALUATION_CONSUMER_ID
            || self.mission_id != self.proposal.scope.mission
            || self.mission_revision != self.proposal.scope.mission_revision
            || self.scope_digest != *self.proposal.scope.digest()
            || self.adopted
            || self.durable
            || self.receipt_candidate.durable
            || self.receipt_candidate.native
            || self.receipt_candidate.connected
        {
            return Err(LangSmithEvaluationError::ProposalTampered);
        }
        self.result_digest.validate("mission_result_digest")?;
        let expected = canonical_digest(&MissionResultIdentity {
            consumer_id: self.consumer_id.clone(),
            mission_id: self.mission_id.clone(),
            mission_revision: self.mission_revision.clone(),
            scope_digest: self.scope_digest.clone(),
            proposal: self.proposal.clone(),
            receipt_candidate: self.receipt_candidate.clone(),
            adopted: self.adopted,
            durable: self.durable,
        });
        if self.result_digest != expected {
            return Err(LangSmithEvaluationError::ProposalTampered);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
struct MissionResultIdentity {
    consumer_id: String,
    mission_id: MissionId,
    mission_revision: Revision,
    scope_digest: Digest,
    proposal: EvaluationResultProposal,
    receipt_candidate: EvaluationReceiptCandidate,
    adopted: bool,
    durable: bool,
}

/// Mission-facing consumer. It binds evaluation evidence to a Mission but has
/// no Outcome, Truth, Work Product, or adoption authority.
#[derive(Clone, Debug)]
pub struct MissionLangSmithEvaluationConsumer {
    service: LangSmithEvaluationService,
}

impl MissionLangSmithEvaluationConsumer {
    #[must_use]
    pub fn new(service: LangSmithEvaluationService) -> Self {
        Self { service }
    }

    #[must_use]
    pub fn service(&self) -> LangSmithEvaluationService {
        self.service.clone()
    }

    pub fn consume(
        &self,
        request: &MissionEvaluationRequest,
    ) -> Result<MissionEvaluationResult, LangSmithEvaluationError> {
        request.validate()?;
        let proposal = self
            .service
            .propose_evaluation(request.evaluation.clone())?;
        if proposal.scope.mission != request.mission_id
            || proposal.scope.mission_revision != request.mission_revision
            || proposal.scope.digest() != &request.scope_digest
        {
            return Err(LangSmithEvaluationError::MissionMismatch);
        }
        let receipt_candidate = self.service.receipt_candidate(&proposal)?;
        let result = MissionEvaluationResult::new(request, proposal, receipt_candidate);
        result.validate()?;
        Ok(result)
    }
}
