//! Typed service seam and reversible registration lifecycle.

use std::collections::BTreeSet;

use crate::{
    model::{
        CohereInferenceError, CohereInferenceScope, InferenceRequest, InferenceResultEvidence,
        InferenceResultProposal, InferenceTask, PluginRegistration, ProviderMode, Revocation,
        RevocationReason,
    },
    provider::{BlockedEnvCode, CohereProvider, RecordedCohereResponse},
};

/// The provider-specific service returns a local redacted observation. It is
/// not a Hartevo kernel Receipt and carries no Effect, Consent, Verification,
/// Truth, or Outcome authority.
#[derive(Clone, Debug)]
pub struct CohereInferenceResultService {
    scope: CohereInferenceScope,
    registration: PluginRegistration,
    provider: CohereProvider,
    replay_guard: BTreeSet<crate::model::Digest>,
}

impl CohereInferenceResultService {
    pub fn new(
        scope: CohereInferenceScope,
        provider: CohereProvider,
    ) -> Result<Self, CohereInferenceError> {
        let registration = PluginRegistration::new(&scope);
        registration.validate_against(&scope)?;
        Ok(Self {
            scope,
            registration,
            provider,
            replay_guard: BTreeSet::new(),
        })
    }

    pub fn scope(&self) -> &CohereInferenceScope {
        &self.scope
    }

    pub fn registration(&self) -> &PluginRegistration {
        &self.registration
    }

    pub fn provider(&self) -> &CohereProvider {
        &self.provider
    }

    pub const fn evidence_mode(&self) -> ProviderMode {
        self.provider.mode()
    }

    pub fn describe_model(&self) -> Result<crate::model::ModelDescription, CohereInferenceError> {
        self.ensure_active()?;
        Ok(self.provider.describe_model(&self.scope))
    }

    /// Compile a bounded, canonical, non-mutating proposal. The input is
    /// borrowed and only its digest and shape are retained in the proposal.
    pub fn compile_inference_proposal(
        &self,
        request: &InferenceRequest,
    ) -> Result<InferenceResultProposal, CohereInferenceError> {
        self.ensure_active()?;
        validate_request(&self.scope, request)?;
        let proposal = InferenceResultProposal::new(&self.scope, &self.registration, request);
        proposal.verify_integrity()?;
        Ok(proposal)
    }

    pub fn compile_proposal(
        &self,
        request: &InferenceRequest,
    ) -> Result<InferenceResultProposal, CohereInferenceError> {
        self.compile_inference_proposal(request)
    }

    /// Record a bounded response frame into redacted Layer-1 evidence.
    pub fn record_inference_receipt(
        &mut self,
        proposal: &InferenceResultProposal,
        response: &RecordedCohereResponse,
    ) -> Result<InferenceResultEvidence, CohereInferenceError> {
        self.ensure_active()?;
        self.validate_proposal_binding(proposal)?;
        let evidence = self
            .provider
            .record(proposal, response, self.scope.policy())?;
        self.remember_recording(&evidence)?;
        Ok(evidence)
    }

    pub fn record_inference_result(
        &mut self,
        proposal: &InferenceResultProposal,
        response: &RecordedCohereResponse,
    ) -> Result<InferenceResultEvidence, CohereInferenceError> {
        self.record_inference_receipt(proposal, response)
    }

    pub fn record_inference_observation(
        &mut self,
        proposal: &InferenceResultProposal,
        response: &RecordedCohereResponse,
    ) -> Result<InferenceResultEvidence, CohereInferenceError> {
        self.record_inference_receipt(proposal, response)
    }

    pub fn record_blocked_env(
        &mut self,
        proposal: &InferenceResultProposal,
        recording_id: impl Into<String>,
        code: BlockedEnvCode,
        latency_ms: u64,
    ) -> Result<InferenceResultEvidence, CohereInferenceError> {
        self.ensure_active()?;
        if self.provider.mode() != ProviderMode::BlockedEnv {
            return Err(CohereInferenceError::BlockedEnvironment(
                "BLOCKED_ENV recording requires BLOCKED_ENV provider mode",
            ));
        }
        let response = RecordedCohereResponse::blocked_env(
            recording_id,
            self.scope.provider_route().provider_id(),
            self.scope.model().model_id(),
            self.scope.model().immutable_revision(),
            code,
            latency_ms,
        );
        self.record_inference_receipt(proposal, &response)
    }

    /// Verify local binding and digest consistency only. This does not issue
    /// kernel Verification or authorize Work Product adoption.
    pub fn verify_inference_result(
        &self,
        proposal: &InferenceResultProposal,
        evidence: &InferenceResultEvidence,
    ) -> Result<(), CohereInferenceError> {
        self.ensure_active()?;
        self.validate_proposal_binding(proposal)?;
        evidence.verify_integrity()?;
        if evidence.proposal_digest != proposal.proposal_digest
            || evidence.registration_digest != *self.registration.registration_digest()
            || evidence.scope_digest != self.scope.digest()
            || evidence.provider_digest != self.scope.provider_digest()
            || evidence.model_digest != self.scope.model_digest()
            || evidence.task_digest != self.scope.task_digest()
            || evidence.permission_digest != self.scope.permission_digest()
            || evidence.consent_digest != self.scope.consent_digest()
            || evidence.policy_digest != self.scope.policy_digest()
            || evidence.model_id != self.scope.model().model_id()
            || evidence.model_revision != self.scope.model().immutable_revision()
            || evidence.request_revision != proposal.request.request_revision
            || evidence.authority.connected()
            || evidence.authority.native()
            || evidence.authority.first_party()
        {
            return Err(CohereInferenceError::ScopeMismatch(
                "result evidence is not bound to this active registration",
            ));
        }
        Ok(())
    }

    pub fn verify(
        &self,
        proposal: &InferenceResultProposal,
        evidence: &InferenceResultEvidence,
    ) -> Result<(), CohereInferenceError> {
        self.verify_inference_result(proposal, evidence)
    }

    pub fn revoke(&mut self, reason: RevocationReason) -> Result<Revocation, CohereInferenceError> {
        self.registration.revoke(reason)
    }

    pub fn restore(&mut self) -> Result<(), CohereInferenceError> {
        self.registration.restore()
    }

    pub fn is_active(&self) -> bool {
        self.registration.is_active()
    }

    fn ensure_active(&self) -> Result<(), CohereInferenceError> {
        self.registration.validate_against(&self.scope)
    }

    fn validate_proposal_binding(
        &self,
        proposal: &InferenceResultProposal,
    ) -> Result<(), CohereInferenceError> {
        proposal.verify_integrity()?;
        if proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
            || proposal.provider_digest != self.scope.provider_digest()
            || proposal.model_digest != self.scope.model_digest()
            || proposal.task_digest != self.scope.task_digest()
            || proposal.permission_digest != self.scope.permission_digest()
            || proposal.consent_digest != self.scope.consent_digest()
            || proposal.policy_digest != self.scope.policy_digest()
            || proposal.task != self.scope.task()
            || proposal.model != *self.scope.model()
            || proposal.provider_route != *self.scope.provider_route()
        {
            return Err(CohereInferenceError::ScopeMismatch(
                "proposal is not bound to the active model, route, task, policy, consent, or registration",
            ));
        }
        Ok(())
    }

    fn remember_recording(
        &mut self,
        evidence: &InferenceResultEvidence,
    ) -> Result<(), CohereInferenceError> {
        if !self.replay_guard.insert(evidence.recording_key.clone()) {
            return Err(CohereInferenceError::ReplayDetected);
        }
        Ok(())
    }
}

fn validate_request(
    scope: &CohereInferenceScope,
    request: &InferenceRequest,
) -> Result<(), CohereInferenceError> {
    if request.request_revision() == 0 {
        return Err(CohereInferenceError::InvalidField {
            field: "request_revision",
            reason: "must be non-zero",
        });
    }
    if request.task() != scope.task() {
        return Err(CohereInferenceError::TaskMismatch);
    }
    if request.options().tool_calls() {
        return Err(CohereInferenceError::ToolCallsForbidden);
    }
    if request.options().stream() {
        return Err(CohereInferenceError::StreamingForbidden);
    }
    if request.options().file_inputs() {
        return Err(CohereInferenceError::FileAuthorityForbidden);
    }
    let input = request.input();
    if input.input_bytes() > scope.policy().max_input_bytes() {
        return Err(CohereInferenceError::InputTooLarge);
    }
    if input.item_count() > scope.policy().max_items() {
        return Err(CohereInferenceError::ItemCountExceeded);
    }
    if input.messages().is_some_and(|messages| {
        messages
            .iter()
            .any(|message| message.content_len() > scope.policy().max_item_bytes())
    }) || input
        .single_text()
        .is_some_and(|text| text.len() > scope.policy().max_item_bytes())
        || input.text_batch().is_some_and(|texts| {
            texts
                .iter()
                .any(|text| text.len() > scope.policy().max_item_bytes())
        })
    {
        return Err(CohereInferenceError::ItemTooLarge);
    }
    match (request.task(), input) {
        (InferenceTask::Chat, crate::model::InferenceInput::Chat(_))
        | (InferenceTask::Generate, crate::model::InferenceInput::Text(_))
        | (InferenceTask::Generate, crate::model::InferenceInput::Texts(_))
        | (InferenceTask::Embed, crate::model::InferenceInput::Text(_))
        | (InferenceTask::Embed, crate::model::InferenceInput::Texts(_)) => {}
        _ => return Err(CohereInferenceError::TaskMismatch),
    }
    if request.generation().max_new_tokens() > scope.policy().max_new_tokens() {
        return Err(CohereInferenceError::GenerationBudgetExceeded);
    }
    Ok(())
}
