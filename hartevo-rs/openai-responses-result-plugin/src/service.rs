//! Typed service lifecycle and local digest/replay authority.

use std::collections::BTreeMap;

use crate::{
    model::{
        BlockedEnvCode, OpenAIResponsesProposal, OpenAIResponsesRequest,
        OpenAIResponsesResultError, OpenAIResponsesResultEvidence, OpenAIResponsesScope,
        PluginRegistration, ProviderMode, Revocation, RevocationReason,
    },
    provider::{ModelDescription, OpenAIResponsesProvider, RecordedResponseFrame},
};

/// The Layer-1 provider-specific service. Its recording method returns local,
/// redacted evidence; it never creates a Hartevo kernel Receipt or authorizes
/// Verification, Truth, Outcome adoption, external writes, or tools.
#[derive(Clone, Debug)]
pub struct OpenAIResponsesResultService {
    scope: OpenAIResponsesScope,
    registration: PluginRegistration,
    provider: OpenAIResponsesProvider,
    replay_guard: BTreeMap<crate::model::Digest, crate::model::Digest>,
}

impl OpenAIResponsesResultService {
    pub fn new(
        scope: OpenAIResponsesScope,
        provider: OpenAIResponsesProvider,
    ) -> Result<Self, OpenAIResponsesResultError> {
        let registration = PluginRegistration::new(&scope);
        registration.validate_against(&scope)?;
        Ok(Self {
            scope,
            registration,
            provider,
            replay_guard: BTreeMap::new(),
        })
    }

    pub fn scope(&self) -> &OpenAIResponsesScope {
        &self.scope
    }

    pub fn registration(&self) -> &PluginRegistration {
        &self.registration
    }

    pub fn provider(&self) -> &OpenAIResponsesProvider {
        &self.provider
    }

    pub const fn evidence_mode(&self) -> ProviderMode {
        self.provider.mode()
    }

    pub fn describe_model(&self) -> Result<ModelDescription, OpenAIResponsesResultError> {
        self.ensure_active()?;
        Ok(self.provider.describe_model(&self.scope))
    }

    pub fn compile_response_proposal(
        &self,
        request: &OpenAIResponsesRequest,
    ) -> Result<OpenAIResponsesProposal, OpenAIResponsesResultError> {
        self.ensure_active()?;
        validate_request(&self.scope, request)?;
        let proposal = OpenAIResponsesProposal::new(&self.scope, &self.registration, request);
        proposal.verify_integrity()?;
        Ok(proposal)
    }

    pub fn compile_responses_proposal(
        &self,
        request: &OpenAIResponsesRequest,
    ) -> Result<OpenAIResponsesProposal, OpenAIResponsesResultError> {
        self.compile_response_proposal(request)
    }

    pub fn compile_request_proposal(
        &self,
        request: &OpenAIResponsesRequest,
    ) -> Result<OpenAIResponsesProposal, OpenAIResponsesResultError> {
        self.compile_response_proposal(request)
    }

    pub fn record_response(
        &mut self,
        proposal: &OpenAIResponsesProposal,
        frame: &RecordedResponseFrame,
    ) -> Result<OpenAIResponsesResultEvidence, OpenAIResponsesResultError> {
        self.ensure_active()?;
        self.validate_proposal_binding(proposal)?;
        let evidence = self.provider.record(&self.scope, proposal, frame)?;
        self.remember_recording(&evidence)?;
        Ok(evidence)
    }

    /// Compatibility vocabulary for a local recording operation. This is not
    /// a kernel Receipt and does not imply native provider connectivity.
    pub fn record_inference_receipt(
        &mut self,
        proposal: &OpenAIResponsesProposal,
        frame: &RecordedResponseFrame,
    ) -> Result<OpenAIResponsesResultEvidence, OpenAIResponsesResultError> {
        self.record_response(proposal, frame)
    }

    pub fn record_blocked_env(
        &mut self,
        proposal: &OpenAIResponsesProposal,
        recording_id: impl Into<String>,
        code: BlockedEnvCode,
        latency_ms: u64,
    ) -> Result<OpenAIResponsesResultEvidence, OpenAIResponsesResultError> {
        if self.provider.mode() != ProviderMode::BlockedEnv {
            return Err(OpenAIResponsesResultError::BlockedEnvironment(
                "BLOCKED_ENV recording requires BLOCKED_ENV provider mode",
            ));
        }
        let frame = RecordedResponseFrame::blocked_env(
            recording_id,
            self.scope.provider().provider_id(),
            self.scope.model().model_id(),
            self.scope.model().immutable_snapshot(),
            code,
            latency_ms,
        );
        self.record_response(proposal, &frame)
    }

    /// Verify only local proposal/evidence bindings. This does not issue a
    /// kernel Verification or authorize Work Product adoption.
    pub fn verify_response(
        &self,
        proposal: &OpenAIResponsesProposal,
        evidence: &OpenAIResponsesResultEvidence,
    ) -> Result<(), OpenAIResponsesResultError> {
        self.ensure_active()?;
        self.validate_proposal_binding(proposal)?;
        evidence.verify_integrity()?;
        if evidence.proposal_digest != proposal.proposal_digest
            || evidence.registration_digest != *self.registration.registration_digest()
            || evidence.provider_digest != self.scope.provider_digest()
            || evidence.organization_digest != self.scope.organization_digest()
            || evidence.project_digest != self.scope.project_digest()
            || evidence.model_snapshot_digest != self.scope.model_digest()
            || evidence.input_policy_digest != self.scope.input_policy_digest()
            || evidence.structured_schema_digest != self.scope.structured_schema_digest()
            || evidence.tool_policy_digest != self.scope.tool_policy_digest()
            || evidence.mission_digest != self.scope.mission_digest()
            || evidence.work_product_digest != self.scope.work_product_digest()
            || evidence.consent_digest != self.scope.consent_digest()
            || evidence.scope_digest != self.scope.digest()
            || evidence.authority.connected
            || evidence.authority.native
            || evidence.authority.external_writes
            || evidence.authority.durable_provider_receipt
            || evidence.authority.independent_read_back
            || evidence.authority.kernel_truth
            || evidence.authority.kernel_verification
            || evidence.authority.kernel_outcome_adoption
            || evidence.authority.tool_execution
            || evidence.authority.web_search
        {
            return Err(OpenAIResponsesResultError::ScopeMismatch(
                "evidence is not bound to the active non-native registration",
            ));
        }
        Ok(())
    }

    pub fn verify_inference_result(
        &self,
        proposal: &OpenAIResponsesProposal,
        evidence: &OpenAIResponsesResultEvidence,
    ) -> Result<(), OpenAIResponsesResultError> {
        self.verify_response(proposal, evidence)
    }

    pub fn revoke(
        &mut self,
        reason: RevocationReason,
    ) -> Result<Revocation, OpenAIResponsesResultError> {
        self.registration.revoke(reason)
    }

    pub fn restore(&mut self) -> Result<(), OpenAIResponsesResultError> {
        self.registration.restore();
        Ok(())
    }

    pub fn is_active(&self) -> bool {
        self.registration.is_active()
    }

    fn ensure_active(&self) -> Result<(), OpenAIResponsesResultError> {
        self.registration.validate_against(&self.scope)
    }

    fn validate_proposal_binding(
        &self,
        proposal: &OpenAIResponsesProposal,
    ) -> Result<(), OpenAIResponsesResultError> {
        proposal.verify_integrity()?;
        if proposal.registration_digest != *self.registration.registration_digest()
            || proposal.provider_digest != self.scope.provider_digest()
            || proposal.organization_digest != self.scope.organization_digest()
            || proposal.project_digest != self.scope.project_digest()
            || proposal.model_snapshot_digest != self.scope.model_digest()
            || proposal.input_policy_digest != self.scope.input_policy_digest()
            || proposal.structured_schema_digest != self.scope.structured_schema_digest()
            || proposal.tool_policy_digest != self.scope.tool_policy_digest()
            || proposal.mission_digest != self.scope.mission_digest()
            || proposal.work_product_digest != self.scope.work_product_digest()
            || proposal.consent_digest != self.scope.consent_digest()
            || proposal.scope_digest != self.scope.digest()
        {
            return Err(OpenAIResponsesResultError::ScopeMismatch(
                "proposal is not bound to the active model, project, policy, consent, or registration",
            ));
        }
        Ok(())
    }

    fn remember_recording(
        &mut self,
        evidence: &OpenAIResponsesResultEvidence,
    ) -> Result<(), OpenAIResponsesResultError> {
        if self.replay_guard.contains_key(&evidence.recording_digest) {
            return Err(OpenAIResponsesResultError::ReplayDetected);
        }
        self.replay_guard.insert(
            evidence.recording_digest.clone(),
            evidence.evidence_digest.clone(),
        );
        Ok(())
    }
}

fn validate_request(
    scope: &OpenAIResponsesScope,
    request: &OpenAIResponsesRequest,
) -> Result<(), OpenAIResponsesResultError> {
    if request.tool_policy() != scope.tool_policy()
        || request.tool_policy().tools_enabled()
        || request.tool_policy().web_search_enabled()
    {
        return Err(OpenAIResponsesResultError::ToolPolicyViolation);
    }
    if request.structured_output_schema() != scope.structured_output_schema() {
        return Err(OpenAIResponsesResultError::StructuredSchemaMismatch);
    }
    let input = request.input();
    let policy = scope.input_policy();
    input.validate()?;
    if input.byte_len() > policy.max_input_bytes() {
        return Err(OpenAIResponsesResultError::InputTooLarge);
    }
    if input.item_count() > policy.max_items() {
        return Err(OpenAIResponsesResultError::InputItemCountExceeded);
    }
    if input.text_bytes() > policy.max_text_bytes() {
        return Err(OpenAIResponsesResultError::TextInputTooLarge);
    }
    if input.image_count() > policy.max_image_references() {
        return Err(OpenAIResponsesResultError::ImageReferenceCountExceeded);
    }
    if input.file_count() > policy.max_file_references() {
        return Err(OpenAIResponsesResultError::FileReferenceCountExceeded);
    }
    if input.undeclared_file(policy) {
        return Err(OpenAIResponsesResultError::UndeclaredFileReference);
    }
    Ok(())
}
