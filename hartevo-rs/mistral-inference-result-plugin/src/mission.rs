//! Mission/Work Product consumer wrapper for the provider-specific seam.

use serde::Serialize;

use crate::{
    digest_serializable,
    model::{
        EvidenceDisposition, InferenceResultEvidence, InferenceResultProposal,
        InferenceResultState, MistralInferenceError, MistralInferenceScope, ModelDescription,
        ModelListEvidence, PluginRegistration, Revocation, RevocationReason,
    },
    provider::{MistralModelListResponse, MistralProvider, RecordedMistralResponse},
    service::MistralInferenceResultService,
};

/// Proposal-only Mission projection. It binds the target Work Product and
/// consent revision but never adopts it or creates kernel Outcome authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionMistralInferenceProjection {
    pub project_id: String,
    pub project_revision: u64,
    pub mission_id: String,
    pub mission_revision: u64,
    pub work_product_id: String,
    pub work_product_revision: u64,
    pub consent_id: String,
    pub consent_revision: u64,
    pub project_scope_digest: crate::model::Digest,
    pub mission_scope_digest: crate::model::Digest,
    pub work_product_scope_digest: crate::model::Digest,
    pub consent_digest: crate::model::Digest,
    pub proposal_digest: crate::model::Digest,
    pub evidence_digest: crate::model::Digest,
    pub state: InferenceResultState,
    pub disposition: EvidenceDisposition,
    proposal_only: bool,
    connected: bool,
    native: bool,
    first_party: bool,
}

pub type MissionResultProjection = MissionMistralInferenceProjection;

impl MissionMistralInferenceProjection {
    fn from_result(
        scope: &MistralInferenceScope,
        proposal: &InferenceResultProposal,
        evidence: &InferenceResultEvidence,
    ) -> Self {
        Self {
            project_id: scope.project().id().to_owned(),
            project_revision: scope.project().revision(),
            mission_id: scope.mission().id().to_owned(),
            mission_revision: scope.mission().revision(),
            work_product_id: scope.work_product().id().to_owned(),
            work_product_revision: scope.work_product().revision(),
            consent_id: scope.consent().id().to_owned(),
            consent_revision: scope.consent().revision(),
            project_scope_digest: digest_serializable(scope.project()),
            mission_scope_digest: digest_serializable(scope.mission()),
            work_product_scope_digest: digest_serializable(scope.work_product()),
            consent_digest: scope.consent_digest(),
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: evidence.evidence_digest.clone(),
            state: evidence.state,
            disposition: evidence.disposition,
            proposal_only: true,
            connected: false,
            native: false,
            first_party: false,
        }
    }

    pub const fn proposal_only(&self) -> bool {
        self.proposal_only
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

/// Mission consumer for one exact Mistral model revision/provider route.
#[derive(Clone, Debug)]
pub struct MissionMistralInferenceConsumer {
    service: MistralInferenceResultService,
}

impl MissionMistralInferenceConsumer {
    pub fn new(
        scope: MistralInferenceScope,
        provider: MistralProvider,
    ) -> Result<Self, MistralInferenceError> {
        Ok(Self {
            service: MistralInferenceResultService::new(scope, provider)?,
        })
    }

    pub fn from_service(service: MistralInferenceResultService) -> Self {
        Self { service }
    }

    pub fn service(&self) -> &MistralInferenceResultService {
        &self.service
    }

    pub fn service_mut(&mut self) -> &mut MistralInferenceResultService {
        &mut self.service
    }

    pub fn registration(&self) -> &PluginRegistration {
        self.service.registration()
    }

    pub fn describe_model(&self) -> Result<ModelDescription, MistralInferenceError> {
        self.service.describe_model()
    }

    pub fn compile_inference_proposal(
        &self,
        request: &crate::model::InferenceRequest,
    ) -> Result<InferenceResultProposal, MistralInferenceError> {
        self.service.compile_inference_proposal(request)
    }

    pub fn consume_recorded_result(
        &mut self,
        proposal: &InferenceResultProposal,
        response: &RecordedMistralResponse,
    ) -> Result<MissionMistralInferenceProjection, MistralInferenceError> {
        let evidence = self.service.record_inference_receipt(proposal, response)?;
        self.service.verify_inference_result(proposal, &evidence)?;
        Ok(MissionMistralInferenceProjection::from_result(
            self.service.scope(),
            proposal,
            &evidence,
        ))
    }

    pub fn consume(
        &mut self,
        proposal: &InferenceResultProposal,
        response: &RecordedMistralResponse,
    ) -> Result<MissionMistralInferenceProjection, MistralInferenceError> {
        self.consume_recorded_result(proposal, response)
    }

    pub fn record_inference_receipt(
        &mut self,
        proposal: &InferenceResultProposal,
        response: &RecordedMistralResponse,
    ) -> Result<InferenceResultEvidence, MistralInferenceError> {
        self.service.record_inference_receipt(proposal, response)
    }

    pub fn record_model_list(
        &mut self,
        response: &MistralModelListResponse,
    ) -> Result<ModelListEvidence, MistralInferenceError> {
        self.service.record_model_list(response)
    }

    pub fn revoke(
        &mut self,
        reason: RevocationReason,
    ) -> Result<Revocation, MistralInferenceError> {
        self.service.revoke(reason)
    }

    pub fn restore(&mut self) -> Result<(), MistralInferenceError> {
        self.service.restore()
    }
}
