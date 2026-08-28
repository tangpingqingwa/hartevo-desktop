//! Proposal-only Mission/Work Product consumer projection.

use serde::Serialize;

use crate::{
    digest_serializable,
    model::{
        EvidenceDisposition, OpenAIResponsesProposal, OpenAIResponsesRequest,
        OpenAIResponsesResultError, OpenAIResponsesResultEvidence, OpenAIResponsesScope,
        PluginRegistration, ResponseStatus, Revocation, RevocationReason,
    },
    provider::{ModelDescription, OpenAIResponsesProvider, RecordedResponseFrame},
    service::OpenAIResponsesResultService,
};

/// A proposal-only Mission projection. It never adopts a Work Product or
/// issues Truth, Receipt, Verification, or Outcome authority.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionResponseProjection {
    pub project_id: String,
    pub project_revision: u64,
    pub mission_id: String,
    pub mission_revision: u64,
    pub work_product_id: String,
    pub work_product_revision: u64,
    pub response_id: Option<String>,
    pub status: ResponseStatus,
    pub evidence_digest: crate::model::Digest,
    pub disposition: EvidenceDisposition,
    pub response_digest: crate::model::Digest,
    proposal_only: bool,
    connected: bool,
    native: bool,
    factual_truth_authority: bool,
    kernel_outcome_adoption: bool,
}

impl MissionResponseProjection {
    fn from_result(scope: &OpenAIResponsesScope, evidence: &OpenAIResponsesResultEvidence) -> Self {
        Self {
            project_id: scope.project().id().to_owned(),
            project_revision: scope.project().revision(),
            mission_id: scope.mission().id().to_owned(),
            mission_revision: scope.mission().revision(),
            work_product_id: scope.work_product().id().to_owned(),
            work_product_revision: scope.work_product().revision(),
            response_id: evidence
                .response_id
                .as_ref()
                .map(|response_id| response_id.as_str().to_owned()),
            status: evidence.status,
            evidence_digest: evidence.evidence_digest.clone(),
            disposition: evidence.disposition,
            response_digest: evidence.response_digest.clone(),
            proposal_only: true,
            connected: false,
            native: false,
            factual_truth_authority: false,
            kernel_outcome_adoption: false,
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

    pub const fn factual_truth_authority(&self) -> bool {
        self.factual_truth_authority
    }

    pub const fn kernel_outcome_adoption(&self) -> bool {
        self.kernel_outcome_adoption
    }
}

#[derive(Clone, Debug)]
pub struct MissionOpenAIResponsesConsumer {
    service: OpenAIResponsesResultService,
}

impl MissionOpenAIResponsesConsumer {
    pub fn new(
        scope: OpenAIResponsesScope,
        provider: OpenAIResponsesProvider,
    ) -> Result<Self, OpenAIResponsesResultError> {
        Ok(Self {
            service: OpenAIResponsesResultService::new(scope, provider)?,
        })
    }

    pub fn from_service(service: OpenAIResponsesResultService) -> Self {
        Self { service }
    }

    pub fn service(&self) -> &OpenAIResponsesResultService {
        &self.service
    }

    pub fn service_mut(&mut self) -> &mut OpenAIResponsesResultService {
        &mut self.service
    }

    pub fn registration(&self) -> &PluginRegistration {
        self.service.registration()
    }

    pub fn describe_model(&self) -> Result<ModelDescription, OpenAIResponsesResultError> {
        self.service.describe_model()
    }

    pub fn compile_response_proposal(
        &self,
        request: &OpenAIResponsesRequest,
    ) -> Result<OpenAIResponsesProposal, OpenAIResponsesResultError> {
        self.service.compile_response_proposal(request)
    }

    pub fn consume_recorded_response(
        &mut self,
        proposal: &OpenAIResponsesProposal,
        frame: &RecordedResponseFrame,
    ) -> Result<MissionResponseProjection, OpenAIResponsesResultError> {
        let evidence = self.service.record_response(proposal, frame)?;
        self.service.verify_response(proposal, &evidence)?;
        Ok(MissionResponseProjection::from_result(
            self.service.scope(),
            &evidence,
        ))
    }

    pub fn record_response(
        &mut self,
        proposal: &OpenAIResponsesProposal,
        frame: &RecordedResponseFrame,
    ) -> Result<OpenAIResponsesResultEvidence, OpenAIResponsesResultError> {
        self.service.record_response(proposal, frame)
    }

    pub fn verify_response(
        &self,
        proposal: &OpenAIResponsesProposal,
        evidence: &OpenAIResponsesResultEvidence,
    ) -> Result<(), OpenAIResponsesResultError> {
        self.service.verify_response(proposal, evidence)
    }

    pub fn revoke(
        &mut self,
        reason: RevocationReason,
    ) -> Result<Revocation, OpenAIResponsesResultError> {
        self.service.revoke(reason)
    }

    pub fn restore(&mut self) -> Result<(), OpenAIResponsesResultError> {
        self.service.restore()
    }
}

#[allow(dead_code)]
fn _projection_digest(projection: &MissionResponseProjection) -> crate::model::Digest {
    digest_serializable(projection)
}
