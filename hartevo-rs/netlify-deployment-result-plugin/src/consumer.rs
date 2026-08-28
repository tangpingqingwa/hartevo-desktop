use std::{collections::BTreeMap, fmt};

use serde::Serialize;

use crate::error::{NetlifyDeploymentError, Result};
use crate::model::{
    Digest, NetlifyDeploymentEvidenceState, NetlifyDeploymentScope, TransportProvenance,
};
use crate::service::{
    NetlifyDeploymentProposal, NetlifyDeploymentRegistration, RegistrationTransitionEvidence,
};
use crate::{CONSUMER_ID, SERVICE_ID};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    New,
    Preparing,
    Prepared,
    Uploading,
    Uploaded,
    Ready,
    Error,
    Canceled,
    Unknown,
    Partial,
    Expired,
    NotFound,
    AccessLoss,
    Throttled,
    Conflict,
    Timeout,
    StaleCommit,
    Tampered,
    ProviderUnknown,
    RegistrationRevoked,
}

impl From<NetlifyDeploymentEvidenceState> for ProposalDisposition {
    fn from(value: NetlifyDeploymentEvidenceState) -> Self {
        match value {
            NetlifyDeploymentEvidenceState::New => Self::New,
            NetlifyDeploymentEvidenceState::Preparing => Self::Preparing,
            NetlifyDeploymentEvidenceState::Prepared => Self::Prepared,
            NetlifyDeploymentEvidenceState::Uploading => Self::Uploading,
            NetlifyDeploymentEvidenceState::Uploaded => Self::Uploaded,
            NetlifyDeploymentEvidenceState::Ready => Self::Ready,
            NetlifyDeploymentEvidenceState::Error => Self::Error,
            NetlifyDeploymentEvidenceState::Canceled => Self::Canceled,
            NetlifyDeploymentEvidenceState::Unknown => Self::Unknown,
            NetlifyDeploymentEvidenceState::Partial => Self::Partial,
            NetlifyDeploymentEvidenceState::Expired => Self::Expired,
            NetlifyDeploymentEvidenceState::NotFound => Self::NotFound,
            NetlifyDeploymentEvidenceState::AccessLoss => Self::AccessLoss,
            NetlifyDeploymentEvidenceState::Throttled => Self::Throttled,
            NetlifyDeploymentEvidenceState::Conflict => Self::Conflict,
            NetlifyDeploymentEvidenceState::Timeout => Self::Timeout,
            NetlifyDeploymentEvidenceState::StaleCommit => Self::StaleCommit,
            NetlifyDeploymentEvidenceState::Tampered => Self::Tampered,
            NetlifyDeploymentEvidenceState::ProviderUnknown => Self::ProviderUnknown,
            NetlifyDeploymentEvidenceState::RegistrationRevoked => Self::RegistrationRevoked,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionNetlifyDeploymentResult {
    pub service_id: String,
    pub consumer_id: String,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub project: crate::model::ProjectProjection,
    pub mission: crate::model::MissionProjection,
    pub work_product: crate::model::WorkProductProjection,
    pub state: NetlifyDeploymentEvidenceState,
    pub disposition: ProposalDisposition,
    pub preview_decision: crate::service::NetlifyPreviewDecision,
    pub deployment: Option<crate::model::DeploymentProjection>,
    pub evidence: crate::service::EvidenceDigests,
    pub provenance: TransportProvenance,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub content_verified: bool,
}

impl MissionNetlifyDeploymentResult {
    #[must_use]
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedNetlifyDeploymentResult {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub state: NetlifyDeploymentEvidenceState,
    pub disposition: ProposalDisposition,
    pub preview_decision: crate::service::NetlifyPreviewDecision,
    pub provenance: TransportProvenance,
    pub replayed: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub content_verified: bool,
    pub recording_digest: Digest,
}

impl RecordedNetlifyDeploymentResult {
    fn new(
        idempotency_key_digest: Digest,
        proposal: &NetlifyDeploymentProposal,
        replayed: bool,
    ) -> Self {
        let mut result = Self {
            idempotency_key_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            state: proposal.state,
            disposition: proposal.state.into(),
            preview_decision: proposal.preview_decision,
            provenance: proposal.provenance.clone(),
            replayed,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            content_verified: false,
            recording_digest: Digest::from_text("unsealed-netlify-recording"),
        };
        result.recording_digest = result.calculate_digest();
        result
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.content_verified
            || self.recording_digest != self.calculate_digest()
        {
            Err(NetlifyDeploymentError::TamperedEvidence)
        } else {
            Ok(())
        }
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "netlify-recording/v1",
            &[
                (
                    "idempotency",
                    self.idempotency_key_digest.as_str().to_owned(),
                ),
                ("proposal", self.proposal_digest.as_str().to_owned()),
                ("state", format!("{:?}", self.state)),
                ("decision", format!("{:?}", self.preview_decision)),
                ("provenance", self.provenance.as_str().to_owned()),
                ("replayed", self.replayed.to_string()),
            ],
        )
    }
}

/// Mission consumer scoped to one exact Project/Mission/Work Product and
/// provider registration. Recording is bounded, redacted, and idempotent.
pub struct MissionNetlifyDeploymentConsumer {
    scope: NetlifyDeploymentScope,
    registration: NetlifyDeploymentRegistration,
    records: BTreeMap<Digest, RecordedNetlifyDeploymentResult>,
}

impl fmt::Debug for MissionNetlifyDeploymentConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionNetlifyDeploymentConsumer")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest(),
            )
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionNetlifyDeploymentConsumer {
    pub fn new(
        scope: NetlifyDeploymentScope,
        registration: NetlifyDeploymentRegistration,
    ) -> Result<Self> {
        registration.validate()?;
        if !registration.is_active() {
            return Err(NetlifyDeploymentError::RegistrationInactive);
        }
        if registration.scope_digest() != &scope.digest() {
            return Err(NetlifyDeploymentError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn registration(&self) -> &NetlifyDeploymentRegistration {
        &self.registration
    }

    #[must_use]
    pub fn registration_mut(&mut self) -> &mut NetlifyDeploymentRegistration {
        &mut self.registration
    }

    #[must_use]
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn revoke_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.revoke()
    }

    pub fn reverse_registration(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.reverse()
    }

    pub fn consume(
        &self,
        proposal: &NetlifyDeploymentProposal,
    ) -> Result<MissionNetlifyDeploymentResult> {
        proposal.validate_integrity()?;
        if !self.registration.is_active() {
            return Err(NetlifyDeploymentError::RegistrationInactive);
        }
        let expected_project = crate::model::ProjectProjection::from(self.scope.project());
        let expected_mission = crate::model::MissionProjection::from(self.scope.mission());
        let expected_work_product =
            crate::model::WorkProductProjection::from(self.scope.work_product());
        if proposal.service_id != SERVICE_ID
            || proposal.consumer_id != CONSUMER_ID
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
            || proposal.project != expected_project
            || proposal.mission != expected_mission
            || proposal.work_product != expected_work_product
        {
            return Err(NetlifyDeploymentError::ScopeMismatch);
        }
        Ok(MissionNetlifyDeploymentResult {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            project: proposal.project.clone(),
            mission: proposal.mission.clone(),
            work_product: proposal.work_product.clone(),
            state: proposal.state,
            disposition: proposal.state.into(),
            preview_decision: proposal.preview_decision,
            deployment: proposal.deployment.clone(),
            evidence: proposal.evidence.evidence.clone(),
            provenance: proposal.provenance.clone(),
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            content_verified: false,
        })
    }

    pub fn record(
        &mut self,
        proposal: &NetlifyDeploymentProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<RecordedNetlifyDeploymentResult> {
        let _ = self.consume(proposal)?;
        if !self.registration.is_active() {
            return Err(NetlifyDeploymentError::RegistrationInactive);
        }
        let key = idempotency_key.as_ref();
        if key.is_empty() || key.len() > crate::model::MAX_IDENTIFIER_BYTES {
            return Err(NetlifyDeploymentError::InvalidRequest);
        }
        let key_digest = Digest::from_text(key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(NetlifyDeploymentError::RecordingConflict);
            }
            let replay = RecordedNetlifyDeploymentResult::new(key_digest, proposal, true);
            replay.validate_integrity()?;
            return Ok(replay);
        }
        let result = RecordedNetlifyDeploymentResult::new(key_digest.clone(), proposal, false);
        result.validate_integrity()?;
        self.records.insert(key_digest, result.clone());
        Ok(result)
    }
}
