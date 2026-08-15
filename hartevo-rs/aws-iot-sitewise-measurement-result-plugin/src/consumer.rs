//! Mission-scoped proposal consumption and idempotent recording.

use std::{collections::BTreeMap, fmt};

use serde::Serialize;

use crate::error::{AwsIoTSiteWiseMeasurementError, Result};
use crate::model::{
    AwsIoTSiteWiseMeasurementScope, Digest, EvidenceDigests, MeasurementAggregate,
    MeasurementEvidenceState, TransportProvenance,
};
use crate::service::{AwsIoTSiteWiseMeasurementProposal, AwsIoTSiteWiseMeasurementRegistration};
use crate::{CONSUMER_ID, SERVICE_ID};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProposalDisposition {
    Present,
    Empty,
    Partial,
    Stale,
    AccessLost,
    ProviderUnknown,
    Tampered,
    Revoked,
}

impl From<MeasurementEvidenceState> for ProposalDisposition {
    fn from(state: MeasurementEvidenceState) -> Self {
        match state {
            MeasurementEvidenceState::Present => Self::Present,
            MeasurementEvidenceState::Empty => Self::Empty,
            MeasurementEvidenceState::Partial => Self::Partial,
            MeasurementEvidenceState::Stale => Self::Stale,
            MeasurementEvidenceState::AccessLost => Self::AccessLost,
            MeasurementEvidenceState::ProviderUnknown => Self::ProviderUnknown,
            MeasurementEvidenceState::Tampered => Self::Tampered,
            MeasurementEvidenceState::Revoked => Self::Revoked,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsIoTSiteWiseResult {
    pub service_id: String,
    pub consumer_id: String,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub mission: crate::model::MissionProjection,
    pub project: crate::model::ProjectProjection,
    pub work_product: crate::model::WorkProductProjection,
    pub state: MeasurementEvidenceState,
    pub disposition: ProposalDisposition,
    pub aggregate: Option<MeasurementAggregate>,
    pub evidence: EvidenceDigests,
    pub provenance: TransportProvenance,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

impl MissionAwsIoTSiteWiseResult {
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedAwsIoTSiteWiseResult {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub state: MeasurementEvidenceState,
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

impl RecordedAwsIoTSiteWiseResult {
    fn new(
        idempotency_key_digest: Digest,
        proposal: &AwsIoTSiteWiseMeasurementProposal,
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
            recording_digest: Digest::from_text("unsealed-aws-iot-sitewise-recording"),
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
            || self.recording_digest != self.calculate_digest()
        {
            Err(AwsIoTSiteWiseMeasurementError::TamperedEvidence)
        } else {
            Ok(())
        }
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-iot-sitewise-recording/v1",
            &[
                (
                    "idempotency",
                    self.idempotency_key_digest.as_str().to_owned(),
                ),
                ("proposal", self.proposal_digest.as_str().to_owned()),
                ("state", format!("{:?}", self.state)),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

/// Mission consumer scoped to one exact version/permission/scope registration.
pub struct MissionAwsIoTSiteWiseConsumer {
    scope: AwsIoTSiteWiseMeasurementScope,
    registration: AwsIoTSiteWiseMeasurementRegistration,
    records: BTreeMap<Digest, RecordedAwsIoTSiteWiseResult>,
}

impl fmt::Debug for MissionAwsIoTSiteWiseConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAwsIoTSiteWiseConsumer")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest(),
            )
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionAwsIoTSiteWiseConsumer {
    pub fn new(
        scope: AwsIoTSiteWiseMeasurementScope,
        registration: AwsIoTSiteWiseMeasurementRegistration,
    ) -> Result<Self> {
        registration.validate()?;
        if registration.scope_digest() != &scope.digest() {
            return Err(AwsIoTSiteWiseMeasurementError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    pub fn registration(&self) -> &AwsIoTSiteWiseMeasurementRegistration {
        &self.registration
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn consume(
        &self,
        proposal: &AwsIoTSiteWiseMeasurementProposal,
    ) -> Result<MissionAwsIoTSiteWiseResult> {
        proposal.validate_integrity()?;
        if proposal.service_id != SERVICE_ID
            || proposal.consumer_id != CONSUMER_ID
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
            || proposal.mission.id_digest != self.scope.mission().digest()
            || proposal.project.id_digest != self.scope.project().digest()
            || proposal.work_product.id_digest != self.scope.work_product().digest()
        {
            return Err(AwsIoTSiteWiseMeasurementError::ScopeMismatch);
        }
        if !self.registration.is_active() && proposal.state != MeasurementEvidenceState::Revoked {
            return Err(AwsIoTSiteWiseMeasurementError::RegistrationInactive);
        }
        Ok(MissionAwsIoTSiteWiseResult {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            mission: proposal.mission.clone(),
            project: proposal.project.clone(),
            work_product: proposal.work_product.clone(),
            state: proposal.state,
            disposition: proposal.state.into(),
            aggregate: proposal.aggregate.clone(),
            evidence: proposal.evidence.clone(),
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
        proposal: &AwsIoTSiteWiseMeasurementProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<RecordedAwsIoTSiteWiseResult> {
        let _ = self.consume(proposal)?;
        let key = idempotency_key.as_ref();
        if key.is_empty() || key.len() > crate::MAX_IDENTIFIER_BYTES {
            return Err(AwsIoTSiteWiseMeasurementError::InvalidRequest);
        }
        let key_digest = Digest::from_text(key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(AwsIoTSiteWiseMeasurementError::RecordingConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            replay.recording_digest = replay.calculate_digest();
            return Ok(replay);
        }
        let result = RecordedAwsIoTSiteWiseResult::new(key_digest.clone(), proposal, false);
        self.records.insert(key_digest, result.clone());
        Ok(result)
    }
}

pub type MissionAwsIoTSiteWiseMeasurementConsumer = MissionAwsIoTSiteWiseConsumer;
