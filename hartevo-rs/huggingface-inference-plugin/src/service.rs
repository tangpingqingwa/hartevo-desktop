//! Typed service seam and reversible registration lifecycle.

use std::collections::BTreeMap;

use crate::{
    model::{
        HuggingFaceInferenceError, HuggingFaceInferenceScope, InferenceRequest,
        InferenceResultEvidence, InferenceResultProposal, InferenceTask, ModelDescription,
        PluginRegistration, ProviderMode, Revocation, RevocationReason,
    },
    provider::{BlockedEnvCode, HuggingFaceInferenceProvider, RecordedProviderResponse},
};

/// The provider-specific typed service.  Its “receipt” method returns only a
/// local redacted recording; it is not a Hartevo kernel Receipt and carries no
/// Effect, Consent, Verification, or Outcome authority.
#[derive(Clone, Debug)]
pub struct HuggingFaceInferenceResultService {
    scope: HuggingFaceInferenceScope,
    registration: PluginRegistration,
    provider: HuggingFaceInferenceProvider,
    replay_guard: BTreeMap<crate::model::Digest, crate::model::Digest>,
}

impl HuggingFaceInferenceResultService {
    pub fn new(
        scope: HuggingFaceInferenceScope,
        provider: HuggingFaceInferenceProvider,
    ) -> Result<Self, HuggingFaceInferenceError> {
        let registration = PluginRegistration::new(&scope);
        registration.validate_against(&scope)?;
        Ok(Self {
            scope,
            registration,
            provider,
            replay_guard: BTreeMap::new(),
        })
    }

    pub fn scope(&self) -> &HuggingFaceInferenceScope {
        &self.scope
    }

    pub fn registration(&self) -> &PluginRegistration {
        &self.registration
    }

    pub fn provider(&self) -> &HuggingFaceInferenceProvider {
        &self.provider
    }

    pub fn evidence_mode(&self) -> ProviderMode {
        self.provider.mode()
    }

    pub fn describe_model(&self) -> Result<ModelDescription, HuggingFaceInferenceError> {
        self.ensure_active()?;
        Ok(self.provider.describe_model(&self.scope))
    }

    pub fn compile_inference_proposal(
        &self,
        request: &InferenceRequest,
    ) -> Result<InferenceResultProposal, HuggingFaceInferenceError> {
        self.ensure_active()?;
        validate_request(&self.scope, request)?;
        let proposal = InferenceResultProposal::new(&self.scope, &self.registration, request);
        proposal.verify_integrity()?;
        Ok(proposal)
    }

    /// Record a bounded response frame.  The raw frame is borrowed and is not
    /// copied into the resulting evidence.  The method name preserves the
    /// issue's typed operation vocabulary, while the return value is a
    /// redacted Layer-1 recording rather than a kernel Receipt.
    pub fn record_inference_receipt(
        &mut self,
        proposal: &InferenceResultProposal,
        response: &RecordedProviderResponse,
    ) -> Result<InferenceResultEvidence, HuggingFaceInferenceError> {
        self.ensure_active()?;
        self.validate_proposal_binding(proposal)?;
        let evidence =
            self.provider
                .record(proposal, response, self.scope.policy().output_redaction())?;
        self.remember_recording(&evidence)?;
        Ok(evidence)
    }

    pub fn record_inference_observation(
        &mut self,
        proposal: &InferenceResultProposal,
        response: &RecordedProviderResponse,
    ) -> Result<InferenceResultEvidence, HuggingFaceInferenceError> {
        self.record_inference_receipt(proposal, response)
    }

    pub fn record_blocked_env(
        &mut self,
        proposal: &InferenceResultProposal,
        recording_id: impl Into<String>,
        code: BlockedEnvCode,
        latency_ms: u64,
    ) -> Result<InferenceResultEvidence, HuggingFaceInferenceError> {
        self.ensure_active()?;
        if self.provider.mode() != ProviderMode::BlockedEnv {
            return Err(HuggingFaceInferenceError::BlockedEnvironment(
                "BLOCKED_ENV recording requires BLOCKED_ENV provider mode",
            ));
        }
        let response = RecordedProviderResponse::blocked_env(
            recording_id,
            self.scope.provider_route().provider_id(),
            self.scope.model().model_id(),
            self.scope.model().immutable_revision(),
            code,
            latency_ms,
        );
        self.record_inference_receipt(proposal, &response)
    }

    /// Verify only local binding and digest consistency.  This does not issue
    /// a kernel Verification or authorize Work Product adoption.
    pub fn verify_inference_result(
        &self,
        proposal: &InferenceResultProposal,
        evidence: &InferenceResultEvidence,
    ) -> Result<(), HuggingFaceInferenceError> {
        self.ensure_active()?;
        self.validate_proposal_binding(proposal)?;
        evidence.verify_integrity()?;
        if evidence.proposal_digest != proposal.proposal_digest
            || evidence.registration_digest != *self.registration.registration_digest()
            || evidence.scope_digest != self.scope.digest()
            || evidence.provider_digest != self.scope.provider_digest()
            || evidence.model_digest != self.scope.model_digest()
            || evidence.task_digest != self.scope.task_digest()
            || evidence.authority.connected()
            || evidence.authority.native()
        {
            return Err(HuggingFaceInferenceError::ScopeMismatch(
                "result evidence is not bound to this active registration",
            ));
        }
        Ok(())
    }

    pub fn revoke(
        &mut self,
        reason: RevocationReason,
    ) -> Result<Revocation, HuggingFaceInferenceError> {
        self.registration.revoke(reason)
    }

    pub fn restore(&mut self) -> Result<(), HuggingFaceInferenceError> {
        self.registration.restore()
    }

    pub fn is_active(&self) -> bool {
        self.registration.is_active()
    }

    fn ensure_active(&self) -> Result<(), HuggingFaceInferenceError> {
        self.registration.validate_against(&self.scope)
    }

    fn validate_proposal_binding(
        &self,
        proposal: &InferenceResultProposal,
    ) -> Result<(), HuggingFaceInferenceError> {
        proposal.verify_integrity()?;
        if proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
            || proposal.provider_digest != self.scope.provider_digest()
            || proposal.model_digest != self.scope.model_digest()
            || proposal.task_digest != self.scope.task_digest()
            || proposal.task != self.scope.task()
            || proposal.model != *self.scope.model()
            || proposal.provider_route != *self.scope.provider_route()
        {
            return Err(HuggingFaceInferenceError::ScopeMismatch(
                "proposal is not bound to the active model, route, task, or registration",
            ));
        }
        Ok(())
    }

    fn remember_recording(
        &mut self,
        evidence: &InferenceResultEvidence,
    ) -> Result<(), HuggingFaceInferenceError> {
        if self.replay_guard.contains_key(&evidence.recording_key) {
            return Err(HuggingFaceInferenceError::ReplayDetected);
        }
        self.replay_guard.insert(
            evidence.recording_key.clone(),
            evidence.evidence_digest.clone(),
        );
        Ok(())
    }
}

fn validate_request(
    scope: &HuggingFaceInferenceScope,
    request: &InferenceRequest,
) -> Result<(), HuggingFaceInferenceError> {
    if request.task() != scope.task() {
        return Err(HuggingFaceInferenceError::TaskMismatch);
    }
    if request.options().tool_calls() {
        return Err(HuggingFaceInferenceError::ToolCallsForbidden);
    }
    if request.options().stream() {
        return Err(HuggingFaceInferenceError::StreamingForbidden);
    }
    let input = request.input();
    if input.input_bytes() > scope.policy().max_input_bytes() {
        return Err(HuggingFaceInferenceError::InputTooLarge);
    }
    if input.item_count() > scope.policy().max_messages() {
        return Err(HuggingFaceInferenceError::MessageCountExceeded);
    }
    if let Some(messages) = input.messages() {
        if request.task() != InferenceTask::ChatCompletion {
            return Err(HuggingFaceInferenceError::TaskMismatch);
        }
        if messages
            .iter()
            .any(|message| message.content_len() > scope.policy().max_message_bytes())
        {
            return Err(HuggingFaceInferenceError::MessageTooLarge);
        }
    }
    if input.text_input().is_some() && request.task() != InferenceTask::TextGeneration {
        return Err(HuggingFaceInferenceError::TaskMismatch);
    }
    if request.generation().max_new_tokens() > scope.policy().max_new_tokens() {
        return Err(HuggingFaceInferenceError::GenerationBudgetExceeded);
    }
    Ok(())
}
