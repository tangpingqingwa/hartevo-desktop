use std::{collections::BTreeMap, fmt};

use serde::Serialize;

use crate::error::{FlyioDeploymentResultError, Result};
use crate::model::{
    AppProjection, CostReceipt, CostSummary, Digest, EvidenceDigests, EvidenceState,
    FlyioDeploymentScope, MachineProjection, MissionProjection, ProjectProjection,
    TransportProvenance, WorkProductProjection,
};
use crate::service::{FlyioDeploymentResultProposal, FlyioDeploymentResultRegistration};
use crate::{CONSUMER_ID, SERVICE_ID};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    Created,
    Starting,
    Started,
    Stopping,
    Stopped,
    Suspended,
    Destroyed,
    Replaced,
    Partial,
    AccessLost,
    ProviderUnknown,
    Tampered,
    Revoked,
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    Throttled,
    ServerError,
    TimedOut,
    ScopeDrift,
    StaleMission,
    PaginationLoop,
}

impl From<EvidenceState> for ProposalDisposition {
    fn from(state: EvidenceState) -> Self {
        match state {
            EvidenceState::Created => Self::Created,
            EvidenceState::Starting => Self::Starting,
            EvidenceState::Started => Self::Started,
            EvidenceState::Stopping => Self::Stopping,
            EvidenceState::Stopped => Self::Stopped,
            EvidenceState::Suspended => Self::Suspended,
            EvidenceState::Destroyed => Self::Destroyed,
            EvidenceState::Replaced => Self::Replaced,
            EvidenceState::Partial => Self::Partial,
            EvidenceState::AccessLost => Self::AccessLost,
            EvidenceState::ProviderUnknown => Self::ProviderUnknown,
            EvidenceState::Tampered => Self::Tampered,
            EvidenceState::Revoked => Self::Revoked,
            EvidenceState::BadRequest => Self::BadRequest,
            EvidenceState::Unauthorized => Self::Unauthorized,
            EvidenceState::Forbidden => Self::Forbidden,
            EvidenceState::NotFound => Self::NotFound,
            EvidenceState::Conflict => Self::Conflict,
            EvidenceState::Throttled => Self::Throttled,
            EvidenceState::ServerError => Self::ServerError,
            EvidenceState::TimedOut => Self::TimedOut,
            EvidenceState::ScopeDrift => Self::ScopeDrift,
            EvidenceState::StaleMission => Self::StaleMission,
            EvidenceState::PaginationLoop => Self::PaginationLoop,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionFlyioDeploymentResult {
    pub service_id: String,
    pub consumer_id: String,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub app: Option<AppProjection>,
    pub machine: Option<MachineProjection>,
    pub mission: MissionProjection,
    pub project: ProjectProjection,
    pub work_product: WorkProductProjection,
    pub state: EvidenceState,
    pub disposition: ProposalDisposition,
    pub evidence: EvidenceDigests,
    pub request_receipts: Vec<crate::model::RequestReceipt>,
    pub cost_receipts: Vec<CostReceipt>,
    pub cost_summary: CostSummary,
    pub provenance: TransportProvenance,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

impl MissionFlyioDeploymentResult {
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedFlyioDeploymentResult {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub state: EvidenceState,
    pub disposition: ProposalDisposition,
    pub provenance: TransportProvenance,
    pub replayed: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub recording_digest: Digest,
}

impl RecordedFlyioDeploymentResult {
    fn new(
        idempotency_key_digest: Digest,
        proposal: &FlyioDeploymentResultProposal,
        replayed: bool,
    ) -> Self {
        let mut result = Self {
            idempotency_key_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            state: proposal.state,
            disposition: proposal.state.into(),
            provenance: proposal.provenance.clone(),
            replayed,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            recording_digest: Digest::from_text("unsealed-flyio-recording"),
        };
        result.recording_digest = recording_digest(&result);
        result
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.recording_digest != recording_digest(self)
        {
            return Err(FlyioDeploymentResultError::TamperedEvidence);
        }
        self.idempotency_key_digest.validate()?;
        self.proposal_digest.validate()
    }
}

fn recording_digest(result: &RecordedFlyioDeploymentResult) -> Digest {
    Digest::from_parts(
        "flyio-recording/v1",
        &[
            (
                "idempotency",
                result.idempotency_key_digest.as_str().to_owned(),
            ),
            ("proposal", result.proposal_digest.as_str().to_owned()),
            ("state", format!("{:?}", result.state)),
            ("provenance", result.provenance.as_str().to_owned()),
        ],
    )
}

/// Mission consumer bound to one exact Fly.io registration and scope.
pub struct MissionFlyioDeploymentConsumer {
    scope: FlyioDeploymentScope,
    registration: FlyioDeploymentResultRegistration,
    records: BTreeMap<Digest, RecordedFlyioDeploymentResult>,
}

impl fmt::Debug for MissionFlyioDeploymentConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionFlyioDeploymentConsumer")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest(),
            )
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionFlyioDeploymentConsumer {
    pub fn new(
        scope: FlyioDeploymentScope,
        registration: FlyioDeploymentResultRegistration,
    ) -> Result<Self> {
        registration.validate()?;
        if !registration.is_active() {
            return Err(FlyioDeploymentResultError::RegistrationInactive);
        }
        if registration.scope_digest() != &scope.digest() {
            return Err(FlyioDeploymentResultError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    pub fn registration(&self) -> &FlyioDeploymentResultRegistration {
        &self.registration
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn consume(
        &self,
        proposal: &FlyioDeploymentResultProposal,
    ) -> Result<MissionFlyioDeploymentResult> {
        proposal.validate_integrity()?;
        if !self.registration.is_active() {
            return Err(FlyioDeploymentResultError::RegistrationInactive);
        }
        if proposal.service_id != SERVICE_ID
            || proposal.consumer_id != CONSUMER_ID
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
            || proposal.mission.id_digest != self.scope.mission_id().digest()
            || proposal.mission.revision != self.scope.mission_revision()
            || proposal.project.id_digest != self.scope.project_id().digest()
            || proposal.project.revision != self.scope.project_revision()
            || proposal.work_product.id_digest != self.scope.work_product_id().digest()
            || proposal.work_product.revision != self.scope.work_product_revision()
        {
            return Err(FlyioDeploymentResultError::ScopeMismatch);
        }
        Ok(MissionFlyioDeploymentResult {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            app: proposal.app.clone(),
            machine: proposal.machine.clone(),
            mission: proposal.mission.clone(),
            project: proposal.project.clone(),
            work_product: proposal.work_product.clone(),
            state: proposal.state,
            disposition: proposal.state.into(),
            evidence: proposal.evidence.clone(),
            request_receipts: proposal.request_receipts.clone(),
            cost_receipts: proposal.cost_receipts.clone(),
            cost_summary: proposal.cost_summary.clone(),
            provenance: proposal.provenance.clone(),
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
        })
    }

    pub fn record(
        &mut self,
        proposal: &FlyioDeploymentResultProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<RecordedFlyioDeploymentResult> {
        let _ = self.consume(proposal)?;
        let key = idempotency_key.as_ref();
        if key.is_empty() || key.len() > crate::MAX_IDENTIFIER_BYTES {
            return Err(FlyioDeploymentResultError::InvalidRequest);
        }
        let key_digest = Digest::from_text(key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(FlyioDeploymentResultError::ReplayConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            replay.recording_digest = recording_digest(&replay);
            replay.validate_integrity()?;
            return Ok(replay);
        }
        let result = RecordedFlyioDeploymentResult::new(key_digest.clone(), proposal, false);
        self.records.insert(key_digest, result.clone());
        Ok(result)
    }
}
