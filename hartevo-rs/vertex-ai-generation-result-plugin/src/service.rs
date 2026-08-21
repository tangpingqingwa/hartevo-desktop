//! Typed service seam and reversible registration lifecycle.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use crate::{
    model::{
        GenerationRequest, GenerationResultEvidence, GenerationResultProposal, InputPart,
        ModelDescription, PluginRegistration, ProviderMode, RequestFingerprint, Revocation,
        RevocationReason, VertexAiGenerationError, VertexAiGenerationScope,
    },
    provider::{BlockedEnvCode, RecordedVertexAiResponse, VertexAiGenerationProvider},
};

/// Provider-specific Layer-1 service. Its result is local redacted evidence,
/// never a kernel Receipt or an authorization to adopt a Work Product.
#[derive(Clone, Debug)]
pub struct VertexAiGenerationResultService {
    scope: VertexAiGenerationScope,
    registration: PluginRegistration,
    provider: VertexAiGenerationProvider,
    trusted_requests: Arc<Mutex<BTreeMap<crate::model::Digest, GenerationRequest>>>,
}

impl VertexAiGenerationResultService {
    pub fn new(
        scope: VertexAiGenerationScope,
        provider: VertexAiGenerationProvider,
    ) -> Result<Self, VertexAiGenerationError> {
        let registration = PluginRegistration::new(&scope);
        registration.validate_against(&scope)?;
        Ok(Self {
            scope,
            registration,
            provider,
            trusted_requests: Arc::new(Mutex::new(BTreeMap::new())),
        })
    }

    pub fn scope(&self) -> &VertexAiGenerationScope {
        &self.scope
    }

    pub fn registration(&self) -> &PluginRegistration {
        &self.registration
    }

    pub fn provider(&self) -> &VertexAiGenerationProvider {
        &self.provider
    }

    pub const fn evidence_mode(&self) -> ProviderMode {
        self.provider.mode()
    }

    pub fn describe_model(&self) -> Result<ModelDescription, VertexAiGenerationError> {
        self.ensure_active()?;
        Ok(self.provider.describe_model(&self.scope))
    }

    pub fn compile_generation_proposal(
        &self,
        request: &GenerationRequest,
    ) -> Result<GenerationResultProposal, VertexAiGenerationError> {
        self.ensure_active()?;
        validate_request(&self.scope, request)?;
        let proposal = GenerationResultProposal::new(&self.scope, &self.registration, request);
        proposal.verify_integrity()?;
        let mut trusted_requests = self.trusted_requests.lock().map_err(|_| {
            VertexAiGenerationError::BlockedEnvironment(
                "trusted request source binding is unavailable",
            )
        })?;
        trusted_requests.insert(proposal.proposal_digest.clone(), request.clone());
        Ok(proposal)
    }

    pub fn compile_proposal(
        &self,
        request: &GenerationRequest,
    ) -> Result<GenerationResultProposal, VertexAiGenerationError> {
        self.compile_generation_proposal(request)
    }

    /// Record one bounded provider frame. The return value is redacted local
    /// evidence, not a durable provider receipt.
    pub fn record_generation_result(
        &mut self,
        proposal: &GenerationResultProposal,
        response: &RecordedVertexAiResponse,
    ) -> Result<GenerationResultEvidence, VertexAiGenerationError> {
        self.ensure_active()?;
        self.validate_proposal_binding(proposal)?;
        let evidence = self.provider.record_scoped(
            proposal,
            response,
            self.scope.response().redaction(),
            &self.scope,
        )?;
        evidence.verify_integrity()?;
        Ok(evidence)
    }

    pub fn record_response(
        &mut self,
        proposal: &GenerationResultProposal,
        response: &RecordedVertexAiResponse,
    ) -> Result<GenerationResultEvidence, VertexAiGenerationError> {
        self.record_generation_result(proposal, response)
    }

    pub fn record_blocked_env(
        &mut self,
        proposal: &GenerationResultProposal,
        recording_id: impl Into<String>,
        code: BlockedEnvCode,
        latency_ms: u64,
    ) -> Result<GenerationResultEvidence, VertexAiGenerationError> {
        self.ensure_active()?;
        if self.provider.mode() != ProviderMode::BlockedEnv {
            return Err(VertexAiGenerationError::BlockedEnvironment(
                "BLOCKED_ENV recording requires BLOCKED_ENV provider mode",
            ));
        }
        let response = RecordedVertexAiResponse::blocked_env(
            recording_id,
            crate::VERTEX_AI_GENERATION_PROVIDER_ID,
            self.scope.google_cloud_project().project_id(),
            self.scope.location().as_str(),
            self.scope.publisher().as_str(),
            self.scope.model().model_id(),
            self.scope.model().immutable_snapshot(),
            code,
            latency_ms,
        );
        self.record_generation_result(proposal, &response)
    }

    /// Check only local digest and scope consistency. This is not kernel
    /// Verification and does not authorize Work Product adoption.
    pub fn verify_generation_result(
        &self,
        proposal: &GenerationResultProposal,
        evidence: &GenerationResultEvidence,
    ) -> Result<(), VertexAiGenerationError> {
        self.ensure_active()?;
        self.validate_proposal_binding(proposal)?;
        evidence.verify_integrity()?;
        if evidence.proposal_digest != proposal.proposal_digest
            || evidence.request_digest != *proposal.request.request_digest()
            || evidence.request_source_fence != *proposal.request.source_fence()
            || evidence.contract_digest != *self.registration.contract_digest()
            || evidence.registration_digest != *self.registration.registration_digest()
            || evidence.provider_digest != self.scope.provider_digest()
            || evidence.permission_digest != self.scope.permission_digest()
            || evidence.scope_digest != self.scope.digest()
            || evidence.project_digest != self.scope.project().digest()
            || evidence.mission_digest != self.scope.mission().digest()
            || evidence.work_product_digest != self.scope.work_product().digest()
            || evidence.consent_digest != self.scope.consent().digest()
            || evidence.google_cloud_project != *self.scope.google_cloud_project()
            || evidence.location != *self.scope.location()
            || evidence.publisher != self.scope.publisher()
            || evidence.model != *self.scope.model()
            || evidence.redaction != self.scope.response().redaction()
            || evidence.authority.connected
            || evidence.authority.native
            || evidence.authority.durable_receipt
            || evidence.authority.independent_read_back
            || evidence.authority.kernel_outcome_adoption
        {
            return Err(VertexAiGenerationError::ScopeMismatch(
                "result evidence is not bound to this active registration",
            ));
        }
        Ok(())
    }

    pub fn verify_result(
        &self,
        proposal: &GenerationResultProposal,
        evidence: &GenerationResultEvidence,
    ) -> Result<(), VertexAiGenerationError> {
        self.verify_generation_result(proposal, evidence)
    }

    pub fn revoke(
        &mut self,
        reason: RevocationReason,
    ) -> Result<Revocation, VertexAiGenerationError> {
        self.registration.revoke(reason)
    }

    pub fn restore(&mut self) -> Result<(), VertexAiGenerationError> {
        self.registration.restore()
    }

    pub fn is_active(&self) -> bool {
        self.registration.is_active()
    }

    fn ensure_active(&self) -> Result<(), VertexAiGenerationError> {
        self.registration.validate_against(&self.scope)
    }

    fn validate_proposal_binding(
        &self,
        proposal: &GenerationResultProposal,
    ) -> Result<(), VertexAiGenerationError> {
        proposal.verify_integrity()?;
        let trusted_request = {
            let trusted_requests = self.trusted_requests.lock().map_err(|_| {
                VertexAiGenerationError::BlockedEnvironment(
                    "trusted request source binding is unavailable",
                )
            })?;
            trusted_requests.get(&proposal.proposal_digest).cloned()
        }
        .ok_or(VertexAiGenerationError::ScopeMismatch(
            "proposal has no trusted canonical request source",
        ))?;
        validate_request(&self.scope, &trusted_request)?;
        let expected_request = RequestFingerprint::from_request(&self.scope, &trusted_request);
        if proposal.request != expected_request {
            return Err(VertexAiGenerationError::ProposalTampered);
        }
        if proposal.service_id != crate::VERTEX_AI_GENERATION_SERVICE_ID
            || proposal.contract_digest != *self.registration.contract_digest()
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.provider_digest != self.scope.provider_digest()
            || proposal.permission_digest != self.scope.permission_digest()
            || proposal.scope_digest != self.scope.digest()
            || proposal.project_digest != self.scope.project().digest()
            || proposal.mission_digest != self.scope.mission().digest()
            || proposal.work_product_digest != self.scope.work_product().digest()
            || proposal.consent_digest != self.scope.consent().digest()
            || proposal.input_policy_digest != self.scope.input_policy_digest()
            || proposal.safety_policy_digest != self.scope.safety_policy_digest()
            || proposal.tool_grounding_policy_digest != self.scope.tool_grounding_policy_digest()
            || proposal.response_digest != self.scope.response_digest()
            || proposal.google_cloud_project != *self.scope.google_cloud_project()
            || proposal.location != *self.scope.location()
            || proposal.api_version != self.scope.api_version()
            || proposal.publisher != self.scope.publisher()
            || proposal.model != *self.scope.model()
        {
            return Err(VertexAiGenerationError::ScopeMismatch(
                "proposal is not bound to the active project, model, policy, or registration",
            ));
        }
        Ok(())
    }
}

fn validate_request(
    scope: &VertexAiGenerationScope,
    request: &GenerationRequest,
) -> Result<(), VertexAiGenerationError> {
    request.input().verify_integrity()?;
    request.validate_bounds()?;
    if request.input().parts().len() > scope.input_policy().max_parts() {
        return Err(VertexAiGenerationError::InputPartCountExceeded);
    }
    if request.input().total_bytes() > scope.input_policy().max_input_bytes() {
        return Err(VertexAiGenerationError::InputTooLarge);
    }
    for part in request.input().parts() {
        if !scope.input_policy().allows(&part.modality()) {
            return Err(VertexAiGenerationError::ModalityForbidden);
        }
        let too_large = match part {
            InputPart::Text { .. } => part.byte_length() > scope.input_policy().max_text_bytes(),
            InputPart::ImageReference { .. } => {
                part.byte_length() > scope.input_policy().max_image_bytes()
            }
            InputPart::DocumentReference { .. } => {
                part.byte_length() > scope.input_policy().max_document_bytes()
            }
        };
        if too_large {
            return Err(VertexAiGenerationError::InputPartTooLarge);
        }
    }
    if request.max_output_tokens() == 0
        || request.max_output_tokens() > scope.response().max_output_tokens()
    {
        return Err(VertexAiGenerationError::OutputTokenBudgetExceeded);
    }
    if request.candidate_count() == 0
        || request.candidate_count() > scope.response().max_candidates()
    {
        return Err(VertexAiGenerationError::CandidateCountExceeded);
    }
    let options = request.options();
    if options.streaming() {
        return Err(VertexAiGenerationError::StreamingForbidden);
    }
    if options.tool_calls() || scope.tool_grounding_policy().allow_tool_calls() {
        return Err(VertexAiGenerationError::ToolCallsForbidden);
    }
    if options.grounding()
        || scope.tool_grounding_policy().allow_grounding()
        || scope.tool_grounding_policy().allow_search_grounding()
        || scope.tool_grounding_policy().allow_maps_grounding()
    {
        return Err(VertexAiGenerationError::GroundingForbidden);
    }
    match (request.output_schema(), scope.response().output_schema()) {
        (None, None) => {}
        (Some(requested), Some(allowed)) if requested == allowed => {}
        _ => return Err(VertexAiGenerationError::SchemaMismatch),
    }
    Ok(())
}
