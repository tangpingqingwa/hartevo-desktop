//! Typed Anthropic Messages service and reversible registration lifecycle.

use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};

use crate::{
    AnthropicMessageResultError, CONTRACT_VERSION, PLUGIN_ID, PLUGIN_VERSION, PROVIDER_ID, Result,
    SCHEMA_VERSION, SERVICE_ID,
    model::{
        AnthropicMessageRequest, AnthropicMessageResultEvidence, AnthropicMessageResultProposal,
        AnthropicRegistration, AnthropicScope, Digest, ProviderDefinition, ProviderProvenance,
        RegistrationRevocation, RegistrationState,
    },
    provider::{AnthropicProvider, ProviderResponseOutcome, RecordedAnthropicResponse},
    transport::{AnthropicTransport, TransportOutcome},
    validate_contract,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnthropicServiceOperation {
    DescribeService,
    CompileMessageProposal,
    RecordMessageResult,
    RecordBlockedEnv,
    PostMessagesTransportSeam,
    VerifyMessageResult,
    Register,
    RevokeRegistration,
    RestoreRegistration,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnthropicServiceDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub plugin_id: String,
    pub plugin_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub operations: Vec<AnthropicServiceOperation>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub external_writes: bool,
    pub durable_receipts: bool,
    pub kernel_authority: bool,
    pub outcome_adoption: bool,
}

impl AnthropicServiceDefinition {
    pub fn layer_one() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            plugin_id: PLUGIN_ID.to_owned(),
            plugin_version: PLUGIN_VERSION.to_owned(),
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: crate::CONSUMER_ID.to_owned(),
            operations: vec![
                AnthropicServiceOperation::DescribeService,
                AnthropicServiceOperation::CompileMessageProposal,
                AnthropicServiceOperation::RecordMessageResult,
                AnthropicServiceOperation::RecordBlockedEnv,
                AnthropicServiceOperation::PostMessagesTransportSeam,
                AnthropicServiceOperation::VerifyMessageResult,
                AnthropicServiceOperation::Register,
                AnthropicServiceOperation::RevokeRegistration,
                AnthropicServiceOperation::RestoreRegistration,
            ],
            read_only: true,
            proposal_only: true,
            recording_only: true,
            external_writes: false,
            durable_receipts: false,
            kernel_authority: false,
            outcome_adoption: false,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != SCHEMA_VERSION
            || self.contract_version != CONTRACT_VERSION
            || self.plugin_id != PLUGIN_ID
            || self.plugin_version != PLUGIN_VERSION
            || self.service_id != SERVICE_ID
            || self.provider_id != PROVIDER_ID
            || self.consumer_id != crate::CONSUMER_ID
            || self.operations.len() != 9
            || !self.read_only
            || !self.proposal_only
            || !self.recording_only
            || self.external_writes
            || self.durable_receipts
            || self.kernel_authority
            || self.outcome_adoption
        {
            return Err(AnthropicMessageResultError::MutationForbidden(
                "invalid Layer-1 service definition",
            ));
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        Digest::from_serializable(self)
    }
}

/// The service owns only in-memory typed registration and replay fences. It
/// has no Store, keyring, kernel, browser, network client, or Outcome authority.
pub struct AnthropicMessageResultService {
    scope: AnthropicScope,
    registration: AnthropicRegistration,
    provider: AnthropicProvider,
    provider_definition: ProviderDefinition,
    definition: AnthropicServiceDefinition,
    replay_guard: BTreeMap<Digest, Digest>,
}

impl fmt::Debug for AnthropicMessageResultService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AnthropicMessageResultService")
            .field("scope_digest", &self.scope.digest())
            .field("registration", &self.registration)
            .field("provider", &self.provider)
            .field("provider_definition", &self.provider_definition)
            .field("definition", &self.definition)
            .field("replay_fence_count", &self.replay_guard.len())
            .finish()
    }
}

impl AnthropicMessageResultService {
    pub fn new(scope: AnthropicScope, provider: AnthropicProvider) -> Result<Self> {
        validate_contract()?;
        scope.validate()?;
        let provider_definition = provider.definition(&scope);
        let registration = AnthropicRegistration::new(&scope, &provider_definition)?;
        let definition = AnthropicServiceDefinition::layer_one();
        definition.validate()?;
        Ok(Self {
            scope,
            registration,
            provider,
            provider_definition,
            definition,
            replay_guard: BTreeMap::new(),
        })
    }

    pub fn scope(&self) -> &AnthropicScope {
        &self.scope
    }

    pub fn registration(&self) -> &AnthropicRegistration {
        &self.registration
    }

    pub fn provider(&self) -> &AnthropicProvider {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AnthropicProvider {
        &mut self.provider
    }

    pub fn provider_definition(&self) -> &ProviderDefinition {
        &self.provider_definition
    }

    pub fn definition(&self) -> &AnthropicServiceDefinition {
        &self.definition
    }

    pub fn is_active(&self) -> bool {
        self.registration.state == RegistrationState::Active
    }

    pub fn compile_message_proposal(
        &self,
        request: &AnthropicMessageRequest,
    ) -> Result<AnthropicMessageResultProposal> {
        self.ensure_active()?;
        AnthropicMessageResultProposal::compile(
            &self.scope,
            &self.registration,
            request,
            &self.provider_definition,
        )
    }

    pub fn compile_message_result_proposal(
        &self,
        request: &AnthropicMessageRequest,
    ) -> Result<AnthropicMessageResultProposal> {
        self.compile_message_proposal(request)
    }

    pub fn record_message_result(
        &mut self,
        proposal: &AnthropicMessageResultProposal,
        response: &RecordedAnthropicResponse<'_>,
    ) -> Result<AnthropicMessageResultEvidence> {
        self.ensure_active()?;
        proposal.validate_for(&self.scope, &self.registration, &self.provider_definition)?;
        let evidence = self
            .provider
            .record(proposal, response, &self.scope.policy)?;
        self.remember_replay(&evidence)?;
        evidence.verify_integrity()?;
        Ok(evidence)
    }

    pub fn record_message_receipt(
        &mut self,
        proposal: &AnthropicMessageResultProposal,
        response: &RecordedAnthropicResponse<'_>,
    ) -> Result<AnthropicMessageResultEvidence> {
        self.record_message_result(proposal, response)
    }

    pub fn record_blocked_env(
        &mut self,
        proposal: &AnthropicMessageResultProposal,
        recording_id: impl Into<String>,
        code: crate::BlockedEnvCode,
        latency_ms: u64,
    ) -> Result<AnthropicMessageResultEvidence> {
        let recording_id = recording_id.into();
        let response = RecordedAnthropicResponse::blocked_env(recording_id, code, latency_ms)
            .with_provenance(ProviderProvenance::BlockedEnv);
        self.record_message_result(proposal, &response)
    }

    /// Run the optional transport seam and record only the bounded projection.
    /// The transport may build a transient request body, but the service keeps
    /// no body bytes and never resolves the opaque API-key reference.
    pub fn record_via_transport<T: AnthropicTransport>(
        &mut self,
        proposal: &AnthropicMessageResultProposal,
        request: &AnthropicMessageRequest,
        transport: &mut T,
        latency_ms: u64,
    ) -> Result<AnthropicMessageResultEvidence> {
        self.ensure_active()?;
        request.validate_for(&self.scope)?;
        if request.digest() != proposal.request_digest {
            return Err(AnthropicMessageResultError::ScopeMismatch);
        }
        let provenance = transport.provenance();
        match transport.post_messages(request, &self.scope) {
            TransportOutcome::Http {
                status,
                body,
                provider_request_id,
                retry_after_seconds,
            } => {
                let response = RecordedAnthropicResponse::new(
                    request.request_id().as_str(),
                    latency_ms,
                    ProviderResponseOutcome::Http {
                        status,
                        body: &body,
                        provider_request_id: provider_request_id.as_deref(),
                        retry_after_seconds,
                    },
                )
                .with_provenance(provenance);
                self.record_message_result(proposal, &response)
            }
            TransportOutcome::Timeout => {
                let response =
                    RecordedAnthropicResponse::timeout(request.request_id().as_str(), latency_ms)
                        .with_provenance(provenance);
                self.record_message_result(proposal, &response)
            }
            TransportOutcome::TransportUnavailable => {
                let response = RecordedAnthropicResponse::transport_unavailable(
                    request.request_id().as_str(),
                    latency_ms,
                )
                .with_provenance(provenance);
                self.record_message_result(proposal, &response)
            }
            TransportOutcome::BlockedEnv { code } => {
                let response = RecordedAnthropicResponse::blocked_env(
                    request.request_id().as_str(),
                    code,
                    latency_ms,
                )
                .with_provenance(ProviderProvenance::BlockedEnv);
                self.record_message_result(proposal, &response)
            }
        }
    }

    pub fn verify_message_result(
        &self,
        proposal: &AnthropicMessageResultProposal,
        evidence: &AnthropicMessageResultEvidence,
    ) -> Result<()> {
        self.ensure_active()?;
        proposal.validate_for(&self.scope, &self.registration, &self.provider_definition)?;
        evidence.verify_integrity()?;
        if evidence.proposal_digest != proposal.proposal_digest
            || evidence.request_digest != proposal.request_digest
            || evidence.registration_digest != self.registration.registration_digest
            || evidence.scope != self.scope
            || evidence.provider_digest != self.provider_definition.provider_digest
            || evidence.api_digest != self.provider_definition.api_digest
            || evidence.model_digest != self.scope.model.digest()
            || evidence.permission_digest != *self.scope.permission_snapshot.digest()
            || evidence.scope_digest != self.scope.digest()
            || evidence.revision_digest != self.provider_definition.revision_digest
            || !evidence.authority.is_non_authoritative()
        {
            return Err(AnthropicMessageResultError::ScopeMismatch);
        }
        Ok(())
    }

    pub fn verify_message_result_evidence(
        &self,
        proposal: &AnthropicMessageResultProposal,
        evidence: &AnthropicMessageResultEvidence,
    ) -> Result<()> {
        self.verify_message_result(proposal, evidence)
    }

    pub fn revoke_registration(&mut self) -> Result<RegistrationRevocation> {
        self.registration.revoke()
    }

    pub fn restore_registration(&mut self) -> Result<()> {
        self.registration.restore()
    }

    pub fn reject_write(&self, operation: &'static str) -> Result<()> {
        Err(AnthropicMessageResultError::MutationForbidden(operation))
    }

    fn ensure_active(&self) -> Result<()> {
        self.registration
            .validate_against(&self.scope, &self.provider_definition)?;
        if !self.registration.is_active() {
            return Err(AnthropicMessageResultError::RegistrationRevoked);
        }
        Ok(())
    }

    fn remember_replay(&mut self, evidence: &AnthropicMessageResultEvidence) -> Result<()> {
        let key = evidence.request_digest.clone();
        let fingerprint = evidence.result_fingerprint();
        if self.replay_guard.contains_key(&key) {
            return Err(AnthropicMessageResultError::ReplayDetected);
        }
        self.replay_guard.insert(key, fingerprint);
        Ok(())
    }
}

pub type AnthropicMessageService = AnthropicMessageResultService;
