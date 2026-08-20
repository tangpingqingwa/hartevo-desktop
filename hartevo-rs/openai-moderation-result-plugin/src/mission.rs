//! Mission-facing, proposal-only projection for moderation evidence.

use serde::Serialize;

use crate::{
    model::{
        AuthorityClaims, CategoryOutcome, Digest, ModerationStatus, OpenAiModerationError,
        OpenAiModerationEvidence, OpenAiModerationProposal, RegistrationRevocation,
        RevocationReason,
    },
    provider::{OpenAiModerationProvider, OpenAiModerationProviderRead, RecordedModerationFrame},
    service::OpenAiModerationService,
};

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionModerationProjection {
    evidence_digest: Digest,
    mission_digest: Digest,
    work_product_digest: Digest,
    status: ModerationStatus,
    flagged: Option<bool>,
    categories: Vec<CategoryOutcome>,
    requires_safety_review: bool,
    proposal_only: bool,
    connected: bool,
    native: bool,
    first_party: bool,
    kernel_authority: bool,
    automatic_blocking: bool,
    notification: bool,
}

impl MissionModerationProjection {
    pub(crate) fn from_evidence(evidence: &OpenAiModerationEvidence) -> Self {
        let requires_safety_review =
            evidence.status().fail_closed() || evidence.flagged() == Some(true);
        Self {
            evidence_digest: evidence.evidence_digest().clone(),
            mission_digest: evidence.mission_digest().clone(),
            work_product_digest: evidence.work_product_digest().clone(),
            status: evidence.status(),
            flagged: evidence.flagged(),
            categories: evidence.categories().to_vec(),
            requires_safety_review,
            proposal_only: true,
            connected: false,
            native: false,
            first_party: false,
            kernel_authority: false,
            automatic_blocking: false,
            notification: false,
        }
    }

    pub fn evidence_digest(&self) -> &Digest {
        &self.evidence_digest
    }

    pub fn mission_digest(&self) -> &Digest {
        &self.mission_digest
    }

    pub fn work_product_digest(&self) -> &Digest {
        &self.work_product_digest
    }

    pub const fn status(&self) -> ModerationStatus {
        self.status
    }

    pub const fn flagged(&self) -> Option<bool> {
        self.flagged
    }

    pub fn categories(&self) -> &[CategoryOutcome] {
        &self.categories
    }

    pub const fn requires_safety_review(&self) -> bool {
        self.requires_safety_review
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

    pub const fn kernel_authority(&self) -> bool {
        self.kernel_authority
    }

    pub const fn automatic_blocking(&self) -> bool {
        self.automatic_blocking
    }

    pub const fn notification(&self) -> bool {
        self.notification
    }
}

/// Mission consumer that verifies an evidence proposal and emits only a
/// review signal. It never adopts a Work Product, blocks content, or notifies
/// a user.
#[derive(Clone, Debug)]
pub struct MissionOpenAiModerationConsumer {
    service: OpenAiModerationService,
}

impl MissionOpenAiModerationConsumer {
    pub fn new(service: OpenAiModerationService) -> Self {
        Self { service }
    }

    pub fn from_service(service: OpenAiModerationService) -> Self {
        Self::new(service)
    }

    pub fn service(&self) -> &OpenAiModerationService {
        &self.service
    }

    pub fn service_mut(&mut self) -> &mut OpenAiModerationService {
        &mut self.service
    }

    pub fn provider(&self) -> &OpenAiModerationProvider {
        self.service.provider()
    }

    pub fn compile_moderation_proposal(
        &self,
        request: crate::model::ModerationRequest,
    ) -> Result<OpenAiModerationProposal, OpenAiModerationError> {
        self.service.compile_moderation_proposal(request)
    }

    pub fn read_moderation(
        &self,
        proposal: &OpenAiModerationProposal,
        frame: &RecordedModerationFrame,
    ) -> Result<OpenAiModerationEvidence, OpenAiModerationError> {
        self.service.read_moderation(proposal, frame)
    }

    pub fn record_moderation(
        &mut self,
        proposal: &OpenAiModerationProposal,
        frame: &RecordedModerationFrame,
    ) -> Result<OpenAiModerationEvidence, OpenAiModerationError> {
        self.service.record_moderation(proposal, frame)
    }

    pub fn consume(
        &self,
        proposal: &OpenAiModerationProposal,
        evidence: &OpenAiModerationEvidence,
    ) -> Result<MissionModerationProjection, OpenAiModerationError> {
        self.service.verify_moderation(proposal, evidence)?;
        Ok(MissionModerationProjection::from_evidence(evidence))
    }

    pub fn verify_moderation(
        &self,
        proposal: &OpenAiModerationProposal,
        evidence: &OpenAiModerationEvidence,
    ) -> Result<MissionModerationProjection, OpenAiModerationError> {
        self.consume(proposal, evidence)
    }

    pub fn revoke(
        &mut self,
        reason: RevocationReason,
    ) -> Result<RegistrationRevocation, OpenAiModerationError> {
        self.service.revoke(reason)
    }

    pub fn restore(&mut self) -> Result<(), OpenAiModerationError> {
        self.service.restore()
    }
}

pub type MissionOpenAIModerationConsumer = MissionOpenAiModerationConsumer;
pub type ModerationMissionConsumer = MissionOpenAiModerationConsumer;

#[allow(dead_code)]
fn _projection_authority() -> AuthorityClaims {
    AuthorityClaims::layer_one()
}

#[allow(dead_code)]
fn _provider_read_type(_: &OpenAiModerationProviderRead) {}
