//! Typed service seam and reversible registration lifecycle.

use std::collections::BTreeSet;

use crate::{
    model::{
        InferenceRequest, InferenceResultEvidence, InferenceResultProposal, InferenceTask,
        MistralInferenceError, MistralInferenceScope, ModelDescription, ModelListEvidence,
        PluginRegistration, ProviderMode, Revocation, RevocationReason,
    },
    provider::{MistralModelListResponse, MistralProvider, RecordedMistralResponse},
};

/// The provider-specific service returns a local redacted observation. It is
/// not a Hartevo kernel Receipt and carries no Effect, Consent, Verification,
/// Truth, or Outcome authority.
#[derive(Clone, Debug)]
pub struct MistralInferenceResultService {
    scope: MistralInferenceScope,
    registration: PluginRegistration,
    provider: MistralProvider,
    replay_guard: BTreeSet<crate::model::Digest>,
    model_list_replay_guard: BTreeSet<crate::model::Digest>,
}

impl MistralInferenceResultService {
    pub fn new(
        scope: MistralInferenceScope,
        provider: MistralProvider,
    ) -> Result<Self, MistralInferenceError> {
        let registration = PluginRegistration::new(&scope);
        registration.validate_against(&scope)?;
        Ok(Self {
            scope,
            registration,
            provider,
            replay_guard: BTreeSet::new(),
            model_list_replay_guard: BTreeSet::new(),
        })
    }

    pub fn scope(&self) -> &MistralInferenceScope {
        &self.scope
    }

    pub fn registration(&self) -> &PluginRegistration {
        &self.registration
    }

    pub fn provider(&self) -> &MistralProvider {
        &self.provider
    }

    pub const fn evidence_mode(&self) -> ProviderMode {
        self.provider.mode()
    }

    pub fn describe_model(&self) -> Result<ModelDescription, MistralInferenceError> {
        self.ensure_active()?;
        Ok(self.provider.describe_model(&self.scope))
    }

    /// Compile a bounded, canonical, non-mutating inference proposal. The
    /// input is borrowed and only its digest/shape is retained in the result.
    pub fn compile_inference_proposal(
        &self,
        request: &InferenceRequest,
    ) -> Result<InferenceResultProposal, MistralInferenceError> {
        self.ensure_active()?;
        validate_request(&self.scope, request)?;
        let proposal = InferenceResultProposal::new(&self.scope, &self.registration, request);
        proposal.verify_integrity()?;
        Ok(proposal)
    }

    pub fn compile_proposal(
        &self,
        request: &InferenceRequest,
    ) -> Result<InferenceResultProposal, MistralInferenceError> {
        self.compile_inference_proposal(request)
    }

    /// Record a bounded response frame into redacted Layer-1 evidence.
    pub fn record_inference_receipt(
        &mut self,
        proposal: &InferenceResultProposal,
        response: &RecordedMistralResponse,
    ) -> Result<InferenceResultEvidence, MistralInferenceError> {
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
        response: &RecordedMistralResponse,
    ) -> Result<InferenceResultEvidence, MistralInferenceError> {
        self.record_inference_receipt(proposal, response)
    }

    pub fn record_inference_observation(
        &mut self,
        proposal: &InferenceResultProposal,
        response: &RecordedMistralResponse,
    ) -> Result<InferenceResultEvidence, MistralInferenceError> {
        self.record_inference_receipt(proposal, response)
    }

    pub fn record_blocked_env(
        &mut self,
        proposal: &InferenceResultProposal,
        recording_id: impl Into<String>,
        code: crate::provider::BlockedEnvCode,
        latency_ms: u64,
    ) -> Result<InferenceResultEvidence, MistralInferenceError> {
        self.ensure_active()?;
        if self.provider.mode() != ProviderMode::BlockedEnv {
            return Err(MistralInferenceError::BlockedEnvironment(
                "BLOCKED_ENV recording requires BLOCKED_ENV provider mode",
            ));
        }
        let response = RecordedMistralResponse::blocked_env(
            recording_id,
            self.scope.provider_route().provider_id(),
            self.scope.model().model_id(),
            self.scope.model().immutable_revision(),
            code,
            latency_ms,
        );
        self.record_inference_receipt(proposal, &response)
    }

    /// Record a model-list observation. A pinned model must occur in the
    /// returned bounded list before the observation is accepted by the
    /// service.
    pub fn record_model_list(
        &mut self,
        response: &MistralModelListResponse,
    ) -> Result<ModelListEvidence, MistralInferenceError> {
        self.ensure_active()?;
        let evidence = self.provider.record_model_list(
            response,
            self.scope.model().model_id(),
            self.scope.policy(),
        )?;
        if !evidence.pinned_model_allowlisted {
            return Err(MistralInferenceError::ModelNotAllowlisted);
        }
        self.remember_model_list(&evidence)?;
        Ok(evidence)
    }

    /// Lower-level read seam for callers that need to inspect a bounded list
    /// even when it does not contain the pinned model. It does not authorize
    /// model selection or inference.
    pub fn observe_model_list(
        &mut self,
        response: &MistralModelListResponse,
    ) -> Result<ModelListEvidence, MistralInferenceError> {
        self.ensure_active()?;
        let evidence = self.provider.record_model_list(
            response,
            self.scope.model().model_id(),
            self.scope.policy(),
        )?;
        self.remember_model_list(&evidence)?;
        Ok(evidence)
    }

    pub fn verify_model_list(
        &self,
        evidence: &ModelListEvidence,
    ) -> Result<(), MistralInferenceError> {
        self.ensure_active()?;
        evidence.verify_integrity()?;
        if !evidence.pinned_model_allowlisted {
            return Err(MistralInferenceError::ModelNotAllowlisted);
        }
        Ok(())
    }

    /// Verify local binding and digest consistency only. This does not issue
    /// kernel Verification or authorize Work Product adoption.
    pub fn verify_inference_result(
        &self,
        proposal: &InferenceResultProposal,
        evidence: &InferenceResultEvidence,
    ) -> Result<(), MistralInferenceError> {
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
            return Err(MistralInferenceError::ScopeMismatch(
                "result evidence is not bound to this active registration",
            ));
        }
        Ok(())
    }

    pub fn revoke(
        &mut self,
        reason: RevocationReason,
    ) -> Result<Revocation, MistralInferenceError> {
        self.registration.revoke(reason)
    }

    pub fn restore(&mut self) -> Result<(), MistralInferenceError> {
        self.registration.restore()
    }

    pub fn is_active(&self) -> bool {
        self.registration.is_active()
    }

    fn ensure_active(&self) -> Result<(), MistralInferenceError> {
        self.registration.validate_against(&self.scope)
    }

    fn validate_proposal_binding(
        &self,
        proposal: &InferenceResultProposal,
    ) -> Result<(), MistralInferenceError> {
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
            return Err(MistralInferenceError::ScopeMismatch(
                "proposal is not bound to the active model, route, task, policy, or registration",
            ));
        }
        Ok(())
    }

    fn remember_recording(
        &mut self,
        evidence: &InferenceResultEvidence,
    ) -> Result<(), MistralInferenceError> {
        if !self.replay_guard.insert(evidence.recording_key.clone()) {
            return Err(MistralInferenceError::ReplayDetected);
        }
        Ok(())
    }

    fn remember_model_list(
        &mut self,
        evidence: &ModelListEvidence,
    ) -> Result<(), MistralInferenceError> {
        if !self
            .model_list_replay_guard
            .insert(evidence.recording_key.clone())
        {
            return Err(MistralInferenceError::ReplayDetected);
        }
        Ok(())
    }
}

fn validate_request(
    scope: &MistralInferenceScope,
    request: &InferenceRequest,
) -> Result<(), MistralInferenceError> {
    if request.request_revision() == 0 {
        return Err(MistralInferenceError::InvalidField {
            field: "request_revision",
            reason: "must be non-zero",
        });
    }
    if request.task() != scope.task() {
        return Err(MistralInferenceError::TaskMismatch);
    }
    if request.options().tool_calls() {
        return Err(MistralInferenceError::ToolCallsForbidden);
    }
    if request.options().stream() {
        return Err(MistralInferenceError::StreamingForbidden);
    }
    if request.options().file_inputs() {
        return Err(MistralInferenceError::FileAuthorityForbidden);
    }
    let input = request.input();
    if input.input_bytes() > scope.policy().max_input_bytes() {
        return Err(MistralInferenceError::InputTooLarge);
    }
    if input.item_count() > scope.policy().max_items() {
        return Err(MistralInferenceError::ItemCountExceeded);
    }
    if input.messages().is_some_and(|messages| {
        messages
            .iter()
            .any(|message| message.content_len() > scope.policy().max_item_bytes())
    }) {
        return Err(MistralInferenceError::ItemTooLarge);
    }
    if input.text_batch().is_some_and(|texts| {
        texts
            .iter()
            .any(|text| text.len() > scope.policy().max_item_bytes())
    }) {
        return Err(MistralInferenceError::ItemTooLarge);
    }
    match (request.task(), input) {
        (InferenceTask::ChatCompletion, crate::model::InferenceInput::Chat(_))
        | (InferenceTask::Embedding, crate::model::InferenceInput::Texts(_))
        | (InferenceTask::Classification, crate::model::InferenceInput::Texts(_)) => {}
        _ => return Err(MistralInferenceError::TaskMismatch),
    }
    if request.generation().max_new_tokens() > scope.policy().max_new_tokens() {
        return Err(MistralInferenceError::GenerationBudgetExceeded);
    }
    Ok(())
}
