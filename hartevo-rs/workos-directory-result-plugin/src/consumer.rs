//! Mission-facing WorkOS Directory evidence consumer.
//!
//! This consumer binds the service to one exact Project/Mission/Consent
//! revision. It never grants access, mutates identity state, or adopts a
//! kernel Outcome/Consent/Effect.

use serde::Serialize;

use crate::model::{Consent, Digest, EvidenceStatus, Mission, Project, ReadBounds};
use crate::service::{
    ReadBackVerification, WorkOsDirectoryEvidence, WorkOsDirectoryRecordedProposal,
    WorkOsDirectoryResultProposal, WorkOsDirectoryResultService,
};
use crate::{Result, WorkOsDirectoryResultError};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionWorkOsDirectoryContext {
    pub project: Project,
    pub mission: Mission,
    pub consent: Consent,
}

impl MissionWorkOsDirectoryContext {
    pub const fn new(project: Project, mission: Mission, consent: Consent) -> Self {
        Self {
            project,
            mission,
            consent,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkOsDirectoryAdoptionProposal {
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
    pub status: EvidenceStatus,
    pub adopted: bool,
    pub mutates_identity: bool,
    pub creates_access_grant: bool,
    pub kernel_identity_authority: bool,
    pub kernel_consent_authority: bool,
    pub effect_authority: bool,
    pub connected: bool,
    pub native: bool,
    pub raw_idp_attributes_retained: bool,
    pub raw_email_retained: bool,
    pub raw_name_retained: bool,
}

pub struct MissionWorkOsDirectoryConsumer {
    service: WorkOsDirectoryResultService,
}

impl std::fmt::Debug for MissionWorkOsDirectoryConsumer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MissionWorkOsDirectoryConsumer")
            .field("service", &self.service)
            .finish()
    }
}

impl MissionWorkOsDirectoryConsumer {
    pub fn new(service: WorkOsDirectoryResultService) -> Self {
        Self { service }
    }

    pub fn service(&self) -> &WorkOsDirectoryResultService {
        &self.service
    }

    pub fn service_mut(&mut self) -> &mut WorkOsDirectoryResultService {
        &mut self.service
    }

    pub fn into_service(self) -> WorkOsDirectoryResultService {
        self.service
    }

    pub const fn is_connected(&self) -> bool {
        false
    }

    pub const fn is_native(&self) -> bool {
        false
    }

    pub fn inspect(
        &self,
        context: &MissionWorkOsDirectoryContext,
        bounds: ReadBounds,
    ) -> Result<WorkOsDirectoryEvidence> {
        self.ensure_context(context)?;
        self.service.read_directory_evidence(bounds)
    }

    pub fn read_for_mission(
        &self,
        context: &MissionWorkOsDirectoryContext,
        bounds: ReadBounds,
    ) -> Result<WorkOsDirectoryEvidence> {
        self.inspect(context, bounds)
    }

    pub fn propose(
        &self,
        context: &MissionWorkOsDirectoryContext,
        evidence: WorkOsDirectoryEvidence,
    ) -> Result<WorkOsDirectoryResultProposal> {
        self.ensure_context(context)?;
        self.service.compile_evidence_proposal(evidence)
    }

    pub fn consume(
        &self,
        context: &MissionWorkOsDirectoryContext,
        evidence: WorkOsDirectoryEvidence,
    ) -> Result<WorkOsDirectoryAdoptionProposal> {
        let proposal = self.propose(context, evidence)?;
        Ok(WorkOsDirectoryAdoptionProposal {
            scope_digest: proposal.scope_digest,
            registration_digest: proposal.registration_digest,
            evidence_digest: proposal.evidence_digest,
            status: proposal.status,
            adopted: false,
            mutates_identity: false,
            creates_access_grant: false,
            kernel_identity_authority: false,
            kernel_consent_authority: false,
            effect_authority: false,
            connected: false,
            native: false,
            raw_idp_attributes_retained: false,
            raw_email_retained: false,
            raw_name_retained: false,
        })
    }

    pub fn record(
        &mut self,
        context: &MissionWorkOsDirectoryContext,
        proposal: &WorkOsDirectoryResultProposal,
    ) -> Result<WorkOsDirectoryRecordedProposal> {
        self.ensure_context(context)?;
        self.service.record_proposal(proposal)
    }

    pub fn read_back(
        &self,
        context: &MissionWorkOsDirectoryContext,
        record: &WorkOsDirectoryRecordedProposal,
    ) -> Result<ReadBackVerification> {
        self.ensure_context(context)?;
        self.service.read_back_record(record)
    }

    fn ensure_context(&self, context: &MissionWorkOsDirectoryContext) -> Result<()> {
        if self.service.scope().matches_mission_context(
            &context.project,
            &context.mission,
            &context.consent,
        ) {
            Ok(())
        } else {
            Err(WorkOsDirectoryResultError::ScopeMismatch)
        }
    }
}
