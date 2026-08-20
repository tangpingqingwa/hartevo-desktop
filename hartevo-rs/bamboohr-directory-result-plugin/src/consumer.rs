//! Mission-facing BambooHR directory evidence consumer.
//!
//! The consumer binds one exact Project/Mission/Consent revision to the
//! service. It never mutates identity, creates an access grant, executes an
//! Effect, adopts Truth, or claims a connected/native provider.

use serde::Serialize;

use crate::model::{Consent, Digest, Mission, Project, ReadBounds, Revision, WorkProduct};
use crate::service::{
    BambooHrDirectoryEvidence, BambooHrDirectoryEvidenceStatus, BambooHrDirectoryProposal,
    BambooHrDirectoryReadBack, BambooHrDirectoryRecordedProposal, BambooHrDirectoryResultService,
};
use crate::{BambooHrDirectoryResultError, Result};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionBambooHrDirectoryContext {
    pub project: Project,
    pub mission: Mission,
    pub work_product: WorkProduct,
    pub consent: Consent,
}

impl MissionBambooHrDirectoryContext {
    #[must_use]
    pub fn new(project: Project, mission: Mission, consent: Consent) -> Self {
        Self {
            project,
            mission,
            work_product: WorkProduct::new(
                "work-product-unbound",
                Revision::new(1).expect("positive revision"),
            )
            .expect("built-in work product is valid"),
            consent,
        }
    }

    #[must_use]
    pub const fn new_with_work_product(
        project: Project,
        mission: Mission,
        work_product: WorkProduct,
        consent: Consent,
    ) -> Self {
        Self {
            project,
            mission,
            work_product,
            consent,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BambooHrDirectoryAdoptionProposal {
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub evidence_digest: Digest,
    pub status: BambooHrDirectoryEvidenceStatus,
    pub review_only: bool,
    pub adopted: bool,
    pub mutates_identity: bool,
    pub creates_access_grant: bool,
    pub kernel_truth_authority: bool,
    pub kernel_consent_authority: bool,
    pub effect_authority: bool,
    pub receipt_authority: bool,
    pub verification_authority: bool,
    pub outcome_authority: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub raw_employee_ids_retained: bool,
    pub raw_field_values_retained: bool,
}

impl BambooHrDirectoryAdoptionProposal {
    #[must_use]
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

pub struct MissionBambooHrDirectoryConsumer {
    service: BambooHrDirectoryResultService,
}

impl std::fmt::Debug for MissionBambooHrDirectoryConsumer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MissionBambooHrDirectoryConsumer")
            .field("service", &self.service)
            .finish()
    }
}

impl MissionBambooHrDirectoryConsumer {
    #[must_use]
    pub fn new(service: BambooHrDirectoryResultService) -> Self {
        Self { service }
    }

    #[must_use]
    pub fn service(&self) -> &BambooHrDirectoryResultService {
        &self.service
    }

    #[must_use]
    pub fn service_mut(&mut self) -> &mut BambooHrDirectoryResultService {
        &mut self.service
    }

    #[must_use]
    pub fn into_service(self) -> BambooHrDirectoryResultService {
        self.service
    }

    #[must_use]
    pub const fn is_connected(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_native(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn is_first_party(&self) -> bool {
        false
    }

    pub fn inspect(
        &self,
        context: &MissionBambooHrDirectoryContext,
        bounds: ReadBounds,
    ) -> Result<BambooHrDirectoryEvidence> {
        self.ensure_context(context)?;
        self.service.read_directory_evidence(bounds)
    }

    pub fn read_for_mission(
        &self,
        context: &MissionBambooHrDirectoryContext,
        bounds: ReadBounds,
    ) -> Result<BambooHrDirectoryEvidence> {
        self.inspect(context, bounds)
    }

    pub fn propose(
        &self,
        context: &MissionBambooHrDirectoryContext,
        evidence: BambooHrDirectoryEvidence,
    ) -> Result<BambooHrDirectoryProposal> {
        self.ensure_context(context)?;
        self.service.compile_evidence_proposal(evidence)
    }

    pub fn consume(
        &self,
        context: &MissionBambooHrDirectoryContext,
        evidence: BambooHrDirectoryEvidence,
    ) -> Result<BambooHrDirectoryAdoptionProposal> {
        let proposal = self.propose(context, evidence)?;
        Ok(BambooHrDirectoryAdoptionProposal {
            scope_digest: proposal.scope_digest,
            registration_digest: proposal.registration_digest,
            evidence_digest: proposal.evidence_digest,
            status: proposal.status,
            review_only: true,
            adopted: false,
            mutates_identity: false,
            creates_access_grant: false,
            kernel_truth_authority: false,
            kernel_consent_authority: false,
            effect_authority: false,
            receipt_authority: false,
            verification_authority: false,
            outcome_authority: false,
            connected: false,
            native: false,
            first_party: false,
            raw_employee_ids_retained: false,
            raw_field_values_retained: false,
        })
    }

    pub fn record(
        &mut self,
        context: &MissionBambooHrDirectoryContext,
        proposal: &BambooHrDirectoryProposal,
    ) -> Result<BambooHrDirectoryRecordedProposal> {
        self.ensure_context(context)?;
        self.service.record_proposal(proposal)
    }

    pub fn read_back(
        &self,
        context: &MissionBambooHrDirectoryContext,
        record: &BambooHrDirectoryRecordedProposal,
    ) -> Result<BambooHrDirectoryReadBack> {
        self.ensure_context(context)?;
        self.service.read_back_record(record)
    }

    fn ensure_context(&self, context: &MissionBambooHrDirectoryContext) -> Result<()> {
        if self
            .service
            .scope()
            .matches_mission_context_with_work_product(
                &context.project,
                &context.mission,
                &context.work_product,
                &context.consent,
            )
        {
            Ok(())
        } else {
            Err(BambooHrDirectoryResultError::ScopeMismatch)
        }
    }
}

pub type MissionBambooHRDirectoryConsumer = MissionBambooHrDirectoryConsumer;
