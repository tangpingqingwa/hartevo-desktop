use std::{collections::BTreeMap, fmt};

use serde::Serialize;

use crate::error::{DigitalOceanAppDeploymentResultError, Result};
use crate::model::{
    CostReceipt, CostSummary, Digest, DigitalOceanAppDeploymentScope, DigitalOceanEvidenceState,
    EvidenceDigests, MissionProjection, ProjectProjection, RequestReceipt, TransportProvenance,
    WorkProductProjection,
};
use crate::service::{DigitalOceanAppDeploymentProposal, DigitalOceanAppDeploymentRegistration};
use crate::{CONSUMER_ID, SERVICE_ID};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    PendingBuild,
    Building,
    PendingDeploy,
    Deploying,
    Active,
    Superseded,
    Error,
    Canceled,
    Partial,
    AccessLoss,
    ProviderUnknown,
    Tampered,
    Revoked,
}

impl From<DigitalOceanEvidenceState> for ProposalDisposition {
    fn from(state: DigitalOceanEvidenceState) -> Self {
        match state {
            DigitalOceanEvidenceState::PendingBuild => Self::PendingBuild,
            DigitalOceanEvidenceState::Building => Self::Building,
            DigitalOceanEvidenceState::PendingDeploy => Self::PendingDeploy,
            DigitalOceanEvidenceState::Deploying => Self::Deploying,
            DigitalOceanEvidenceState::Active => Self::Active,
            DigitalOceanEvidenceState::Superseded => Self::Superseded,
            DigitalOceanEvidenceState::Error => Self::Error,
            DigitalOceanEvidenceState::Canceled => Self::Canceled,
            DigitalOceanEvidenceState::Partial => Self::Partial,
            DigitalOceanEvidenceState::AccessLost => Self::AccessLoss,
            DigitalOceanEvidenceState::ProviderUnknown => Self::ProviderUnknown,
            DigitalOceanEvidenceState::Tampered => Self::Tampered,
            DigitalOceanEvidenceState::Revoked => Self::Revoked,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionDigitalOceanAppDeploymentResult {
    pub service_id: String,
    pub consumer_id: String,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub mission: MissionProjection,
    pub project: ProjectProjection,
    pub work_product: WorkProductProjection,
    pub state: DigitalOceanEvidenceState,
    pub disposition: ProposalDisposition,
    pub evidence: EvidenceDigests,
    pub request_receipts: Vec<RequestReceipt>,
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

impl MissionDigitalOceanAppDeploymentResult {
    #[must_use]
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedDigitalOceanAppDeploymentResult {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub state: DigitalOceanEvidenceState,
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

impl RecordedDigitalOceanAppDeploymentResult {
    fn new(
        idempotency_key_digest: Digest,
        proposal: &DigitalOceanAppDeploymentProposal,
        replayed: bool,
    ) -> Self {
        let mut result = Self {
            idempotency_key_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            state: proposal.state,
            disposition: proposal.state.into(),
            provenance: proposal.provenance,
            replayed,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            recording_digest: Digest::from_text("unsealed-digitalocean-recording"),
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
            return Err(DigitalOceanAppDeploymentResultError::TamperedEvidence);
        }
        self.idempotency_key_digest.validate()?;
        self.proposal_digest.validate()
    }
}

fn recording_digest(result: &RecordedDigitalOceanAppDeploymentResult) -> Digest {
    Digest::from_parts(
        "digitalocean-recording/v1",
        &[
            (
                "idempotency",
                result.idempotency_key_digest.as_str().to_owned(),
            ),
            ("proposal", result.proposal_digest.as_str().to_owned()),
            ("state", format!("{:?}", result.state)),
            ("provenance", result.provenance.as_str().to_owned()),
            ("replayed", result.replayed.to_string()),
        ],
    )
}

pub struct MissionDigitalOceanAppDeploymentConsumer {
    scope: DigitalOceanAppDeploymentScope,
    registration: DigitalOceanAppDeploymentRegistration,
    expected_mission_revision: u64,
    records: BTreeMap<Digest, RecordedDigitalOceanAppDeploymentResult>,
}

impl fmt::Debug for MissionDigitalOceanAppDeploymentConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionDigitalOceanAppDeploymentConsumer")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                self.registration.registration_digest(),
            )
            .field("expected_mission_revision", &self.expected_mission_revision)
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionDigitalOceanAppDeploymentConsumer {
    pub fn new(
        scope: DigitalOceanAppDeploymentScope,
        registration: DigitalOceanAppDeploymentRegistration,
    ) -> Result<Self> {
        Self::with_mission_revision(scope, registration, None)
    }

    pub fn with_mission_revision(
        scope: DigitalOceanAppDeploymentScope,
        registration: DigitalOceanAppDeploymentRegistration,
        expected_mission_revision: Option<u64>,
    ) -> Result<Self> {
        registration.validate()?;
        if !registration.is_active() {
            return Err(DigitalOceanAppDeploymentResultError::RegistrationInactive);
        }
        if registration.scope_digest() != scope.digest() {
            return Err(DigitalOceanAppDeploymentResultError::ScopeMismatch);
        }
        Ok(Self {
            expected_mission_revision: expected_mission_revision
                .unwrap_or_else(|| scope.mission().revision()),
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn registration(&self) -> &DigitalOceanAppDeploymentRegistration {
        &self.registration
    }
    #[must_use]
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn consume(
        &self,
        proposal: &DigitalOceanAppDeploymentProposal,
    ) -> Result<MissionDigitalOceanAppDeploymentResult> {
        self.consume_with_mission_revision(proposal, self.expected_mission_revision)
    }

    pub fn consume_with_mission_revision(
        &self,
        proposal: &DigitalOceanAppDeploymentProposal,
        mission_revision: u64,
    ) -> Result<MissionDigitalOceanAppDeploymentResult> {
        proposal.validate_integrity()?;
        if !self.registration.is_active() {
            return Err(DigitalOceanAppDeploymentResultError::RegistrationInactive);
        }
        if mission_revision != self.expected_mission_revision
            || proposal.mission.revision != mission_revision
        {
            return Err(DigitalOceanAppDeploymentResultError::StaleMission);
        }
        if proposal.service_id != SERVICE_ID
            || proposal.consumer_id != CONSUMER_ID
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
            || proposal.account_digest != self.scope.account().digest()
            || proposal.team_digest != self.scope.team().digest()
            || proposal.app_digest != self.scope.app().digest()
            || proposal.deployment_digest != self.scope.deployment().digest()
            || proposal.region_digest != self.scope.region().digest()
            || proposal.source_revision_digest != *self.scope.source_revision().digest()
            || proposal.mission.id_digest != self.scope.mission().id_digest()
            || proposal.project.id_digest != self.scope.project().id_digest()
            || proposal.work_product.id_digest != self.scope.work_product().id_digest()
        {
            return Err(DigitalOceanAppDeploymentResultError::ScopeMismatch);
        }
        Ok(MissionDigitalOceanAppDeploymentResult {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            mission: proposal.mission.clone(),
            project: proposal.project.clone(),
            work_product: proposal.work_product.clone(),
            state: proposal.state,
            disposition: proposal.state.into(),
            evidence: proposal.evidence.clone(),
            request_receipts: proposal.request_receipts.clone(),
            cost_receipts: proposal.cost_receipts.clone(),
            cost_summary: proposal.cost_summary.clone(),
            provenance: proposal.provenance,
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
        proposal: &DigitalOceanAppDeploymentProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<RecordedDigitalOceanAppDeploymentResult> {
        let _ = self.consume(proposal)?;
        let key = idempotency_key.as_ref();
        if key.is_empty() || key.len() > crate::MAX_IDENTIFIER_BYTES {
            return Err(DigitalOceanAppDeploymentResultError::InvalidRequest);
        }
        let key_digest = Digest::from_text(key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(DigitalOceanAppDeploymentResultError::ReplayConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            replay.recording_digest = recording_digest(&replay);
            replay.validate_integrity()?;
            return Ok(replay);
        }
        let result =
            RecordedDigitalOceanAppDeploymentResult::new(key_digest.clone(), proposal, false);
        self.records.insert(key_digest, result.clone());
        Ok(result)
    }
}

pub type MissionDigitalOceanAppDeploymentResultProjection = MissionDigitalOceanAppDeploymentResult;
