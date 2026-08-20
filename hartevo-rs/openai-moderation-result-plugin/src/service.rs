//! Service orchestration for the bounded `OpenAI` Moderation Layer-1 seam.

use std::collections::BTreeSet;

use serde::Serialize;

use crate::{
    digest_serializable,
    model::{
        AuthorityClaims, BlockedEnvCode, Digest, ModerationEvidence, ModerationInput,
        ModerationRequest, ModerationStatus, OpenAiModerationError, OpenAiModerationEvidence,
        OpenAiModerationProposal, OpenAiModerationProviderScope, OpenAiModerationRegistration,
        OpenAiModerationScope, ProviderMode, RedactionMetadata, RegistrationRevocation,
        RevocationReason,
    },
    provider::{OpenAiModerationProvider, OpenAiModerationProviderRead, RecordedModerationFrame},
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModerationModelDescription {
    model_id: String,
    immutable_snapshot: String,
    model_digest: Digest,
    provider_id: String,
    api_path: String,
    connected: bool,
    native: bool,
    first_party: bool,
}

impl ModerationModelDescription {
    pub fn model_id(&self) -> &str {
        &self.model_id
    }

    pub fn immutable_snapshot(&self) -> &str {
        &self.immutable_snapshot
    }

    pub fn model_digest(&self) -> &Digest {
        &self.model_digest
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn api_path(&self) -> &str {
        &self.api_path
    }

    pub const fn connected(&self) -> bool {
        self.connected
    }

    pub const fn native(&self) -> bool {
        self.native
    }

    pub const fn first_party(&self) -> bool {
        self.first_party
    }
}

/// Binds one provider, model, policy, input scope, and evidence mode to a
/// reversible registration. It never performs external I/O.
#[derive(Clone, Debug)]
pub struct OpenAiModerationService {
    scope: OpenAiModerationScope,
    provider: OpenAiModerationProvider,
    registration: OpenAiModerationRegistration,
    recorded_fingerprints: BTreeSet<Digest>,
}

impl OpenAiModerationService {
    pub fn new(
        scope: OpenAiModerationScope,
        provider: OpenAiModerationProvider,
    ) -> Result<Self, OpenAiModerationError> {
        scope.policy().validate()?;
        let registration = OpenAiModerationRegistration::bind(
            &scope,
            provider.provider_digest(),
            provider.evidence_binding_digest(),
        );
        Ok(Self {
            scope,
            provider,
            registration,
            recorded_fingerprints: BTreeSet::new(),
        })
    }

    pub fn scope(&self) -> &OpenAiModerationScope {
        &self.scope
    }

    pub fn provider(&self) -> &OpenAiModerationProvider {
        &self.provider
    }

    pub fn registration(&self) -> &OpenAiModerationRegistration {
        &self.registration
    }

    pub const fn evidence_mode(&self) -> ProviderMode {
        self.provider.mode()
    }

    pub fn describe_model(&self) -> Result<ModerationModelDescription, OpenAiModerationError> {
        self.ensure_registration()?;
        Ok(ModerationModelDescription {
            model_id: self.scope.model().model_id().to_owned(),
            immutable_snapshot: self.scope.model().immutable_snapshot().to_owned(),
            model_digest: self.scope.model_digest(),
            provider_id: self.scope.provider().provider_id().to_owned(),
            api_path: self.scope.provider().api_path().to_owned(),
            connected: self.provider.connected(),
            native: self.provider.native(),
            first_party: self.provider.first_party(),
        })
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn compile_moderation_proposal(
        &self,
        request: ModerationRequest,
    ) -> Result<OpenAiModerationProposal, OpenAiModerationError> {
        self.ensure_registration()?;
        request.input().validate(self.scope.policy())?;
        let input = crate::model::InputDescriptor::from_input(request.input());
        let request_fingerprint = digest_serializable(&(
            "hartevo:openai-moderation-request-fingerprint:v1",
            self.registration.registration_digest(),
            request.request_id(),
            request.input_digest(),
            self.provider.provider_digest(),
            self.scope.project_digest(),
            self.scope.mission_digest(),
            self.scope.work_product_digest(),
            self.scope.model_digest(),
            self.scope.policy_digest(),
            self.scope.category_allowlist_digest(),
        ));
        Ok(OpenAiModerationProposal::new(
            request.request_id().clone(),
            self.registration.registration_digest().clone(),
            self.provider.provider_digest(),
            self.scope.project_digest(),
            self.scope.mission_digest(),
            self.scope.work_product_digest(),
            self.scope.model_digest(),
            self.scope.policy_digest(),
            self.scope.category_allowlist_digest(),
            input,
            request_fingerprint,
        ))
    }

    pub fn propose(
        &self,
        request: ModerationRequest,
    ) -> Result<OpenAiModerationProposal, OpenAiModerationError> {
        self.compile_moderation_proposal(request)
    }

    pub fn read_moderation(
        &self,
        proposal: &OpenAiModerationProposal,
        frame: &RecordedModerationFrame,
    ) -> Result<OpenAiModerationEvidence, OpenAiModerationError> {
        self.validate_proposal(proposal)?;
        let read = self
            .provider
            .read(proposal, frame, self.scope.model(), self.scope.policy())?;
        Ok(self.evidence_from_read(proposal, &read, false))
    }

    pub fn read(
        &self,
        proposal: &OpenAiModerationProposal,
        frame: &RecordedModerationFrame,
    ) -> Result<OpenAiModerationEvidence, OpenAiModerationError> {
        self.read_moderation(proposal, frame)
    }

    pub fn record_moderation(
        &mut self,
        proposal: &OpenAiModerationProposal,
        frame: &RecordedModerationFrame,
    ) -> Result<OpenAiModerationEvidence, OpenAiModerationError> {
        self.validate_proposal(proposal)?;
        if self
            .recorded_fingerprints
            .contains(proposal.request_fingerprint())
        {
            return Err(OpenAiModerationError::ReplayDetected);
        }
        let read = self
            .provider
            .read(proposal, frame, self.scope.model(), self.scope.policy())?;
        let evidence = self.evidence_from_read(proposal, &read, true);
        self.recorded_fingerprints
            .insert(proposal.request_fingerprint().clone());
        Ok(evidence)
    }

    pub fn record(
        &mut self,
        proposal: &OpenAiModerationProposal,
        frame: &RecordedModerationFrame,
    ) -> Result<OpenAiModerationEvidence, OpenAiModerationError> {
        self.record_moderation(proposal, frame)
    }

    pub fn record_json(
        &mut self,
        proposal: &OpenAiModerationProposal,
        recording_id: impl Into<String>,
        body: &[u8],
    ) -> Result<OpenAiModerationEvidence, OpenAiModerationError> {
        let frame = RecordedModerationFrame::from_json(
            recording_id,
            proposal.input_digest().clone(),
            body,
        )?;
        self.record_moderation(proposal, &frame)
    }

    pub fn record_blocked_env(
        &mut self,
        proposal: &OpenAiModerationProposal,
        recording_id: impl Into<String>,
        code: BlockedEnvCode,
    ) -> Result<OpenAiModerationEvidence, OpenAiModerationError> {
        let frame = RecordedModerationFrame::blocked_env(
            recording_id,
            self.scope.model().model_id(),
            proposal.input_digest().clone(),
            code,
        )?;
        self.record_moderation(proposal, &frame)
    }

    pub fn verify_moderation(
        &self,
        proposal: &OpenAiModerationProposal,
        evidence: &OpenAiModerationEvidence,
    ) -> Result<(), OpenAiModerationError> {
        evidence.verify_integrity()?;
        self.validate_proposal(proposal)?;
        if evidence.registration_digest() != self.registration.registration_digest()
            || evidence.provider_digest() != self.registration.provider_digest()
            || evidence.project_digest() != proposal.project_digest()
            || evidence.mission_digest() != proposal.mission_digest()
            || evidence.work_product_digest() != proposal.work_product_digest()
            || evidence.model_digest() != proposal.model_digest()
            || evidence.policy_digest() != proposal.policy_digest()
            || evidence.category_allowlist_digest() != proposal.category_allowlist_digest()
            || evidence.input_digest() != proposal.input_digest()
            || evidence.request_fingerprint() != proposal.request_fingerprint()
            || evidence.evidence_mode() != self.provider.mode()
            || !evidence.frame_digest().is_sha256()
        {
            return Err(OpenAiModerationError::EvidenceTampered);
        }
        let authority = evidence.authority();
        if authority.connected()
            || authority.native()
            || authority.first_party()
            || authority.external_writes()
            || authority.automatic_blocking()
            || authority.automatic_deletion()
            || authority.notification()
            || authority.kernel_authority()
            || evidence.redaction().raw_content_retained()
            || evidence.redaction().raw_provider_json_retained()
            || evidence.redaction().hidden_reasoning_retained()
            || evidence.redaction().user_pii_retained()
        {
            return Err(OpenAiModerationError::EvidenceTampered);
        }
        if evidence.status() == ModerationStatus::Completed {
            if evidence.flagged().is_none()
                || evidence.categories().len()
                    != self.scope.policy().categories().categories().len()
                || evidence.categories().iter().any(|outcome| {
                    !self
                        .scope
                        .policy()
                        .categories()
                        .contains(outcome.category())
                })
            {
                return Err(OpenAiModerationError::PartialProviderResponse);
            }
        } else if evidence.flagged().is_some() || !evidence.categories().is_empty() {
            return Err(OpenAiModerationError::EvidenceTampered);
        }
        Ok(())
    }

    pub fn verify(
        &self,
        proposal: &OpenAiModerationProposal,
        evidence: &OpenAiModerationEvidence,
    ) -> Result<(), OpenAiModerationError> {
        self.verify_moderation(proposal, evidence)
    }

    pub fn revoke(
        &mut self,
        reason: RevocationReason,
    ) -> Result<RegistrationRevocation, OpenAiModerationError> {
        self.registration.revoke(reason)
    }

    pub fn restore(&mut self) -> Result<(), OpenAiModerationError> {
        self.registration.restore()
    }

    pub fn is_active(&self) -> bool {
        self.registration.is_active()
    }

    pub fn execute_native(
        &self,
        input: &ModerationInput,
    ) -> Result<RecordedModerationFrame, OpenAiModerationError> {
        self.provider.execute_native(input)
    }

    fn ensure_registration(&self) -> Result<(), OpenAiModerationError> {
        self.registration.validate_against(
            &self.scope,
            &self.provider.provider_digest(),
            &self.provider.evidence_binding_digest(),
        )
    }

    fn validate_proposal(
        &self,
        proposal: &OpenAiModerationProposal,
    ) -> Result<(), OpenAiModerationError> {
        self.ensure_registration()?;
        proposal.verify_integrity()?;
        if proposal.project_digest() != &self.scope.project_digest() {
            return Err(OpenAiModerationError::ProjectRevisionDrift);
        }
        if proposal.mission_digest() != &self.scope.mission_digest() {
            return Err(OpenAiModerationError::MissionRevisionDrift);
        }
        if proposal.work_product_digest() != &self.scope.work_product_digest() {
            return Err(OpenAiModerationError::WorkProductRevisionDrift);
        }
        if proposal.model_digest() != &self.scope.model_digest() {
            return Err(OpenAiModerationError::ModelDrift);
        }
        if proposal.policy_digest() != &self.scope.policy_digest() {
            return Err(OpenAiModerationError::PolicyDrift);
        }
        if proposal.category_allowlist_digest() != &self.scope.category_allowlist_digest() {
            return Err(OpenAiModerationError::CategoryAllowlistDrift);
        }
        if proposal.registration_digest() != self.registration.registration_digest()
            || proposal.provider_digest() != &self.provider.provider_digest()
        {
            return Err(OpenAiModerationError::ScopeMismatch(
                "provider or registration",
            ));
        }
        Ok(())
    }

    fn evidence_from_read(
        &self,
        proposal: &OpenAiModerationProposal,
        read: &OpenAiModerationProviderRead,
        recorded: bool,
    ) -> OpenAiModerationEvidence {
        OpenAiModerationEvidence::new(
            proposal,
            self.provider.mode(),
            read.status(),
            read.flagged(),
            read.categories().to_vec(),
            read.frame_digest().clone(),
            read.response_id_digest().cloned(),
            read.failure(),
            read.latency_ms(),
            recorded,
            RedactionMetadata::for_policy(self.scope.policy().redaction()),
        )
    }
}

pub type OpenAIModerationService = OpenAiModerationService;
pub type ModerationService = OpenAiModerationService;
pub type ModerationModel = ModerationModelDescription;
pub type ModerationProviderScope = OpenAiModerationProviderScope;
pub type ModerationEvidenceResult = ModerationEvidence;

// Keep the public alias visible to downstream crates that use the older
// all-caps naming convention without changing the issue-facing type.
pub type OpenAIResultService = OpenAiModerationService;

#[allow(dead_code)]
fn _layer_one_authority() -> AuthorityClaims {
    AuthorityClaims::layer_one()
}
