use crate::error::{BedrockError, Result};
use crate::model::{
    BedrockScope, ContentBlockKind, DestinationEvidence, GuardrailProjection,
    InferenceContentBlock, InferenceRequest, InferenceResultProposal, InvocationProposal,
    InvocationReceipt, Layer1Provenance, MissionContext, ModelCapabilitySnapshot, RegistrationId,
    ResultDisposition, StopReason, UntrustedToolUseProposal, VerificationFailure,
    VerificationReport,
};
use crate::provider::{BedrockConverseProvider, ProviderContentBlock, ProviderResponse};
use crate::registration::{
    RegistrationRecord, RegistrationRegistry, RegistrationSpec, RevocationReason,
};

#[derive(Debug)]
pub struct BedrockInferenceService {
    provider: BedrockConverseProvider,
    registry: RegistrationRegistry,
}

impl BedrockInferenceService {
    pub fn new(provider: BedrockConverseProvider) -> Self {
        Self {
            provider,
            registry: RegistrationRegistry::default(),
        }
    }

    pub fn with_registry(
        provider: BedrockConverseProvider,
        registry: RegistrationRegistry,
    ) -> Self {
        Self { provider, registry }
    }

    pub fn provider_provenance(&self) -> Layer1Provenance {
        self.provider.provenance()
    }

    pub fn register(&mut self, spec: RegistrationSpec) -> Result<RegistrationId> {
        self.registry.register(spec)
    }

    pub fn revoke(&mut self, id: RegistrationId, reason: RevocationReason) -> Result<()> {
        self.registry.revoke(id, reason)
    }

    pub fn restore(&mut self, id: RegistrationId) -> Result<RegistrationId> {
        self.registry.restore(id)
    }

    pub fn registration(&self, id: RegistrationId) -> Result<&RegistrationRecord> {
        self.registry.get(id)
    }

    pub fn describe_capabilities(&self, id: RegistrationId) -> Result<ModelCapabilitySnapshot> {
        Ok(self
            .registry
            .validate_active(id)?
            .spec()
            .capability()
            .clone())
    }

    pub fn compile_invocation_proposal(
        &self,
        id: RegistrationId,
        mission: &MissionContext,
        request: InferenceRequest,
    ) -> Result<InvocationProposal> {
        let record = self.registry.validate_active(id)?;
        ensure_mission_matches(record.spec().scope(), mission)?;
        request.config().validate(
            record.spec().scope().budget_policy(),
            record.spec().capability().max_output_tokens(),
        )?;
        InvocationProposal::new(
            id,
            record.spec().scope().clone(),
            record.spec().capability(),
            request,
        )
    }

    pub fn invoke_converse(&self, proposal: &InvocationProposal) -> Result<InvocationReceipt> {
        let response = self.provider.invoke_converse(proposal)?;
        self.record_invocation_receipt(proposal, &response)
    }

    pub fn invoke_and_project(
        &self,
        proposal: &InvocationProposal,
    ) -> Result<(InvocationReceipt, InferenceResultProposal)> {
        let response = self.provider.invoke_converse(proposal)?;
        let receipt = self.record_invocation_receipt(proposal, &response)?;
        let result = self.project_inference_result(proposal, &receipt, &response)?;
        Ok((receipt, result))
    }

    pub fn record_invocation_receipt(
        &self,
        proposal: &InvocationProposal,
        response: &ProviderResponse,
    ) -> Result<InvocationReceipt> {
        let record = self.active_record_for_proposal(proposal)?;
        validate_response_scope(record.spec().scope(), response)?;
        let usage = response.usage().receipt()?;
        let budget = record.spec().scope().budget_policy();
        if usage.input_tokens() > budget.max_input_tokens()
            || usage.output_tokens() > budget.max_output_tokens()
            || usage.total_tokens() > budget.max_total_tokens()
        {
            return Err(BedrockError::Transport {
                class: "usage_budget_exceeded",
            });
        }
        if response.latency_ms() > budget.max_latency_ms() {
            return Err(BedrockError::Transport {
                class: "latency_budget_exceeded",
            });
        }
        validate_stop_and_safety(response.stop_reason(), response.safety())?;
        let result_digest = result_digest(proposal, response, &usage);
        Ok(InvocationReceipt::new(
            proposal.registration_id(),
            proposal.request_digest(),
            proposal.content_digest(),
            proposal.tool_schema_digest(),
            proposal.config_digest(),
            proposal.scope_digest(),
            proposal.capability_snapshot_digest(),
            response.aws_request_id().map(str::to_owned),
            response.model_identity().cloned(),
            response.stop_reason(),
            usage,
            proposal.request().config().service_tier(),
            response.latency_ms(),
            response.safety().clone(),
            result_digest,
            response.content_digest(),
            response.destination().clone(),
            response.provenance(),
        ))
    }

    pub fn project_inference_result(
        &self,
        proposal: &InvocationProposal,
        receipt: &InvocationReceipt,
        response: &ProviderResponse,
    ) -> Result<InferenceResultProposal> {
        if receipt.request_digest() != proposal.request_digest()
            || receipt.registration_id() != proposal.registration_id()
        {
            return Err(BedrockError::RequestDigestMismatch);
        }
        let expected_result_digest = result_digest(proposal, response, receipt.usage());
        if receipt.result_digest() != expected_result_digest {
            return Err(BedrockError::ResultDigestMismatch);
        }
        let blocks = response
            .content()
            .iter()
            .map(project_content_block)
            .collect::<Vec<_>>();
        let disposition = disposition_for(response.stop_reason());
        Ok(InferenceResultProposal::new(
            proposal.registration_id(),
            proposal.request_digest(),
            receipt.result_digest(),
            response.content_digest(),
            blocks,
            response.stop_reason(),
            receipt.usage().clone(),
            response.safety().clone(),
            disposition,
            response.provenance(),
        ))
    }

    pub fn verify_inference_result(
        &self,
        proposal: &InvocationProposal,
        receipt: &InvocationReceipt,
        result: &InferenceResultProposal,
    ) -> Result<VerificationReport> {
        let record = self.registry.get(proposal.registration_id())?;
        let mut failures = Vec::new();
        if !record.is_active() {
            failures.push(VerificationFailure::RegistrationInactive);
        }
        if receipt.request_digest() != proposal.request_digest()
            || result.request_digest() != proposal.request_digest()
        {
            failures.push(VerificationFailure::RequestDigestMismatch);
        }
        if receipt.content_digest() != proposal.content_digest()
            || receipt.tool_schema_digest() != proposal.tool_schema_digest()
            || receipt.config_digest() != proposal.config_digest()
        {
            failures.push(VerificationFailure::ConfigDigestMismatch);
        }
        if receipt.result_digest() != result.result_digest() {
            failures.push(VerificationFailure::ResultDigestMismatch);
        }
        if receipt.scope_digest() != proposal.scope_digest()
            || result.registration_id() != proposal.registration_id()
        {
            failures.push(VerificationFailure::ScopeDigestMismatch);
        }
        if receipt.capability_snapshot_digest() != proposal.capability_snapshot_digest() {
            failures.push(VerificationFailure::CapabilityDigestMismatch);
        }
        if receipt.usage() != result.usage()
            || result
                .usage()
                .input_tokens()
                .saturating_add(result.usage().output_tokens())
                != result.usage().total_tokens()
        {
            failures.push(VerificationFailure::UsageMismatch);
        }
        if result.adopts_outcome() {
            failures.push(VerificationFailure::OutcomeAdoptionAttempt);
        }
        if result.provenance().is_live() || receipt.provenance().is_live() {
            failures.push(VerificationFailure::LiveProvenance);
        }
        Ok(VerificationReport::new(failures))
    }

    fn active_record_for_proposal(
        &self,
        proposal: &InvocationProposal,
    ) -> Result<&RegistrationRecord> {
        let record = self.registry.validate_active(proposal.registration_id())?;
        if record.spec().scope().digest() != proposal.scope_digest()
            || record.spec().capability().digest() != proposal.capability_snapshot_digest()
        {
            return Err(BedrockError::RegistrationStale);
        }
        Ok(record)
    }
}

fn ensure_mission_matches(scope: &BedrockScope, mission: &MissionContext) -> Result<()> {
    if scope.project_id() != mission.project_id()
        || scope.mission_id() != mission.mission_id()
        || scope.mission_revision() != mission.mission_revision()
        || scope.budget_policy().digest() != mission.budget_policy().digest()
    {
        return Err(BedrockError::MissionScopeMismatch);
    }
    Ok(())
}

fn validate_response_scope(scope: &BedrockScope, response: &ProviderResponse) -> Result<()> {
    if let Some(model) = response.model_identity()
        && model != scope.model_or_inference_profile()
    {
        return Err(BedrockError::ProviderModelMismatch);
    }
    if let DestinationEvidence::ProviderVerified { region } = response.destination()
        && !scope.routing_policy().permits(region)
    {
        return Err(BedrockError::ProviderRoutingMismatch);
    }
    Ok(())
}

fn validate_stop_and_safety(stop_reason: StopReason, safety: &GuardrailProjection) -> Result<()> {
    let consistent = match stop_reason {
        StopReason::GuardrailIntervened => matches!(safety, GuardrailProjection::Intervened { .. }),
        StopReason::ContentFiltered => {
            matches!(safety, GuardrailProjection::ContentFiltered { .. })
        }
        StopReason::EndTurn
        | StopReason::ToolUse
        | StopReason::MaxTokens
        | StopReason::StopSequence
        | StopReason::Unknown => !matches!(safety, GuardrailProjection::Intervened { .. }),
    };
    if !consistent {
        return Err(BedrockError::ProviderGuardrailMismatch);
    }
    Ok(())
}

fn result_digest(
    proposal: &InvocationProposal,
    response: &ProviderResponse,
    usage: &crate::UsageReceipt,
) -> crate::Digest {
    crate::Digest::of_str(&format!(
        "request={};response={};scope={};stop={};usage={};safety={};content={}",
        proposal.request_digest(),
        response.response_digest(),
        proposal.scope_digest(),
        response.stop_reason().as_str(),
        usage.digest(),
        response.safety().digest(),
        response.content_digest(),
    ))
}

fn project_content_block(block: &ProviderContentBlock) -> InferenceContentBlock {
    match block {
        ProviderContentBlock::Text { content_digest } => InferenceContentBlock::Text {
            content_digest: *content_digest,
        },
        ProviderContentBlock::ToolUse {
            tool_use_digest,
            tool_name_digest,
            input_digest,
        } => InferenceContentBlock::ToolUse {
            proposal: UntrustedToolUseProposal::new(
                *tool_use_digest,
                *tool_name_digest,
                *input_digest,
            ),
        },
        ProviderContentBlock::Unknown { block_digest } => InferenceContentBlock::Unknown {
            block_digest: *block_digest,
        },
    }
}

fn disposition_for(stop_reason: StopReason) -> ResultDisposition {
    match stop_reason {
        StopReason::ToolUse => ResultDisposition::NeedsKernelConsent,
        StopReason::GuardrailIntervened | StopReason::ContentFiltered => {
            ResultDisposition::SafetyBlocked
        }
        StopReason::MaxTokens => ResultDisposition::Truncated,
        StopReason::Unknown => ResultDisposition::ProviderUnknown,
        StopReason::EndTurn | StopReason::StopSequence => ResultDisposition::ProposalOnly,
    }
}

#[allow(dead_code)]
fn _keep_content_kind_typed(kind: ContentBlockKind) -> ContentBlockKind {
    kind
}
