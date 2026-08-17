//! Mission/Work Product consumer wrapper for the provider-specific seam.

use serde::Serialize;

use crate::{
    digest_serializable,
    model::{
        EvidenceDisposition, HuggingFaceInferenceError, HuggingFaceInferenceScope,
        InferenceResultEvidence, InferenceResultProposal, ModelDescription, PluginRegistration,
        Revocation, RevocationReason,
    },
    provider::{HuggingFaceInferenceProvider, RecordedProviderResponse},
    service::HuggingFaceInferenceResultService,
};

/// A proposal-only Mission projection.  It identifies the scoped Work Product
/// target but never adopts it or creates kernel Outcome authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionResultProjection {
    pub project_id: String,
    pub project_revision: u64,
    pub mission_id: String,
    pub mission_revision: u64,
    pub work_product_id: String,
    pub work_product_revision: u64,
    pub project_scope_digest: crate::model::Digest,
    pub mission_scope_digest: crate::model::Digest,
    pub work_product_scope_digest: crate::model::Digest,
    pub evidence_digest: crate::model::Digest,
    pub disposition: EvidenceDisposition,
    proposal_only: bool,
    connected: bool,
    native: bool,
}

impl MissionResultProjection {
    fn from_result(scope: &HuggingFaceInferenceScope, evidence: &InferenceResultEvidence) -> Self {
        Self {
            project_id: scope.project().id().to_owned(),
            project_revision: scope.project().revision(),
            mission_id: scope.mission().id().to_owned(),
            mission_revision: scope.mission().revision(),
            work_product_id: scope.work_product().id().to_owned(),
            work_product_revision: scope.work_product().revision(),
            project_scope_digest: digest_serializable(scope.project()),
            mission_scope_digest: digest_serializable(scope.mission()),
            work_product_scope_digest: digest_serializable(scope.work_product()),
            evidence_digest: evidence.evidence_digest.clone(),
            disposition: evidence.disposition,
            proposal_only: true,
            connected: false,
            native: false,
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
}

/// Mission consumer for one exact HF model revision/provider route binding.
#[derive(Clone, Debug)]
pub struct MissionHuggingFaceResultConsumer {
    service: HuggingFaceInferenceResultService,
}

impl MissionHuggingFaceResultConsumer {
    pub fn new(
        scope: HuggingFaceInferenceScope,
        provider: HuggingFaceInferenceProvider,
    ) -> Result<Self, HuggingFaceInferenceError> {
        Ok(Self {
            service: HuggingFaceInferenceResultService::new(scope, provider)?,
        })
    }

    pub fn from_service(service: HuggingFaceInferenceResultService) -> Self {
        Self { service }
    }

    pub fn service(&self) -> &HuggingFaceInferenceResultService {
        &self.service
    }

    pub fn service_mut(&mut self) -> &mut HuggingFaceInferenceResultService {
        &mut self.service
    }

    pub fn registration(&self) -> &PluginRegistration {
        self.service.registration()
    }

    pub fn describe_model(&self) -> Result<ModelDescription, HuggingFaceInferenceError> {
        self.service.describe_model()
    }

    pub fn compile_inference_proposal(
        &self,
        request: &crate::model::InferenceRequest,
    ) -> Result<InferenceResultProposal, HuggingFaceInferenceError> {
        self.service.compile_inference_proposal(request)
    }

    pub fn consume_recorded_result(
        &mut self,
        proposal: &InferenceResultProposal,
        response: &RecordedProviderResponse,
    ) -> Result<MissionResultProjection, HuggingFaceInferenceError> {
        let evidence = self.service.record_inference_receipt(proposal, response)?;
        self.service.verify_inference_result(proposal, &evidence)?;
        Ok(MissionResultProjection::from_result(
            self.service.scope(),
            &evidence,
        ))
    }

    pub fn record_inference_receipt(
        &mut self,
        proposal: &InferenceResultProposal,
        response: &RecordedProviderResponse,
    ) -> Result<InferenceResultEvidence, HuggingFaceInferenceError> {
        self.service.record_inference_receipt(proposal, response)
    }

    pub fn revoke(
        &mut self,
        reason: RevocationReason,
    ) -> Result<Revocation, HuggingFaceInferenceError> {
        self.service.revoke(reason)
    }

    pub fn restore(&mut self) -> Result<(), HuggingFaceInferenceError> {
        self.service.restore()
    }
}
