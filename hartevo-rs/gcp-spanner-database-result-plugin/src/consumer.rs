//! Mission-scoped, review-only consumption below the Hartevo kernel.

use std::{collections::BTreeSet, fmt};

use thiserror::Error;

use crate::model::{Digest, MissionBinding, ProjectBinding, WorkProductBinding};
use crate::provider::GcpSpannerTransport;
use crate::service::{
    GcpSpannerDatabaseEvidenceState, GcpSpannerDatabaseResultEvidence,
    GcpSpannerDatabaseResultProposal, GcpSpannerDatabaseResultService,
    GcpSpannerDatabaseResultServiceError,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MissionGcpSpannerDatabaseConsumerError {
    #[error("Mission Spanner consumer is revoked")]
    Revoked,
    #[error("Mission Spanner registration does not match the proposal")]
    RegistrationMismatch,
    #[error("Mission binding is stale")]
    StaleMission,
    #[error("Mission Spanner proposal replay was rejected")]
    ReplayDetected,
    #[error("Mission Spanner proposal is invalid")]
    InvalidProposal,
    #[error(transparent)]
    Service(#[from] GcpSpannerDatabaseResultServiceError),
}

pub type MissionGcpSpannerConsumerError = MissionGcpSpannerDatabaseConsumerError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MissionGcpSpannerDatabaseResult {
    pub project: ProjectBinding,
    pub mission: MissionBinding,
    pub work_product: WorkProductBinding,
    pub evidence: GcpSpannerDatabaseResultEvidence,
    pub proposal_digest: Digest,
    pub state: GcpSpannerDatabaseEvidenceState,
    pub proposal_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub adopts_outcome: bool,
    pub adopts_work_product: bool,
}

/// A Mission consumer that can inspect a proposal or local recording but
/// cannot adopt a kernel Outcome, Receipt, Effect, Truth, or Work Product.
pub struct MissionGcpSpannerDatabaseConsumer<T: GcpSpannerTransport> {
    service: GcpSpannerDatabaseResultService<T>,
    mission_digest: Digest,
    mission_revision: u64,
    active: bool,
    consumed_proposals: BTreeSet<Digest>,
}

impl<T: GcpSpannerTransport> fmt::Debug for MissionGcpSpannerDatabaseConsumer<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionGcpSpannerDatabaseConsumer")
            .field("scope_digest", &self.service.scope().digest())
            .field("mission_digest", &self.mission_digest)
            .field("mission_revision", &self.mission_revision)
            .field("active", &self.active)
            .field("consumed_proposals", &self.consumed_proposals.len())
            .finish()
    }
}

impl<T: GcpSpannerTransport> MissionGcpSpannerDatabaseConsumer<T> {
    pub fn new(
        service: GcpSpannerDatabaseResultService<T>,
    ) -> Result<Self, MissionGcpSpannerDatabaseConsumerError> {
        let mission = service.scope().mission().clone();
        Ok(Self {
            mission_digest: mission.digest(),
            mission_revision: mission.revision.get(),
            service,
            active: true,
            consumed_proposals: BTreeSet::new(),
        })
    }

    pub fn for_mission(
        service: GcpSpannerDatabaseResultService<T>,
        mission: MissionBinding,
    ) -> Result<Self, MissionGcpSpannerDatabaseConsumerError> {
        if mission.digest() != service.scope().mission().digest()
            || mission.revision.get() != service.scope().mission().revision.get()
        {
            return Err(MissionGcpSpannerDatabaseConsumerError::StaleMission);
        }
        Self::new(service)
    }

    #[must_use]
    pub fn from_service(service: GcpSpannerDatabaseResultService<T>) -> Self {
        let mission = service.scope().mission().clone();
        Self {
            mission_digest: mission.digest(),
            mission_revision: mission.revision.get(),
            service,
            active: true,
            consumed_proposals: BTreeSet::new(),
        }
    }

    #[must_use]
    pub fn service(&self) -> &GcpSpannerDatabaseResultService<T> {
        &self.service
    }

    #[must_use]
    pub fn service_mut(&mut self) -> &mut GcpSpannerDatabaseResultService<T> {
        &mut self.service
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub fn consume(
        &mut self,
        proposal: &GcpSpannerDatabaseResultProposal,
    ) -> Result<MissionGcpSpannerDatabaseResult, MissionGcpSpannerDatabaseConsumerError> {
        self.ensure_active()?;
        if self.service.scope().mission().digest() != self.mission_digest
            || self.service.scope().mission().revision.get() != self.mission_revision
        {
            return Err(MissionGcpSpannerDatabaseConsumerError::StaleMission);
        }
        let report = self.service.verify(proposal);
        if !report.valid {
            if report
                .failures
                .iter()
                .any(|failure| failure.contains("scope/provider/registration"))
            {
                return Err(MissionGcpSpannerDatabaseConsumerError::RegistrationMismatch);
            }
            return Err(MissionGcpSpannerDatabaseConsumerError::InvalidProposal);
        }
        if !self
            .consumed_proposals
            .insert(proposal.proposal_digest.clone())
        {
            return Err(MissionGcpSpannerDatabaseConsumerError::ReplayDetected);
        }
        Ok(MissionGcpSpannerDatabaseResult {
            project: self.service.scope().project_binding().clone(),
            mission: self.service.scope().mission().clone(),
            work_product: self.service.scope().work_product().clone(),
            evidence: proposal.evidence.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            state: proposal.state,
            proposal_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            adopts_outcome: false,
            adopts_work_product: false,
        })
    }

    pub fn consume_proposal(
        &mut self,
        proposal: &GcpSpannerDatabaseResultProposal,
    ) -> Result<MissionGcpSpannerDatabaseResult, MissionGcpSpannerDatabaseConsumerError> {
        self.consume(proposal)
    }

    pub fn record_and_consume(
        &mut self,
        proposal: &GcpSpannerDatabaseResultProposal,
    ) -> Result<MissionGcpSpannerDatabaseResult, MissionGcpSpannerDatabaseConsumerError> {
        self.service.record(proposal)?;
        self.consume(proposal)
    }

    pub fn revoke(&mut self) -> Result<(), MissionGcpSpannerDatabaseConsumerError> {
        self.ensure_active()?;
        self.service.revoke()?;
        self.active = false;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), MissionGcpSpannerDatabaseConsumerError> {
        if self.active {
            return Err(MissionGcpSpannerDatabaseConsumerError::InvalidProposal);
        }
        self.service.restore_registration()?;
        self.active = true;
        Ok(())
    }

    fn ensure_active(&self) -> Result<(), MissionGcpSpannerDatabaseConsumerError> {
        if self.active {
            Ok(())
        } else {
            Err(MissionGcpSpannerDatabaseConsumerError::Revoked)
        }
    }
}
