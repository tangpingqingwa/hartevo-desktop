//! Mission-scoped proposal consumption and idempotent recording.

use std::{collections::BTreeMap, fmt};

use serde::Serialize;

use crate::error::{AwsCleanRoomsQueryResultError, Result};
use crate::model::{
    AwsCleanRoomsQueryResultScope, Digest, EvidenceDigests, ProtectedQueryStatus,
    TransportProvenance,
};
use crate::service::{AwsCleanRoomsQueryResultProposal, AwsCleanRoomsQueryResultRegistration};
use crate::{CONSUMER_ID, SERVICE_ID};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    Submitted,
    Started,
    Cancelling,
    Success,
    Failed,
    Cancelled,
    TimedOut,
    Partial,
    AccessLost,
    ProviderUnknown,
    Tampered,
    Revoked,
}

impl From<ProtectedQueryStatus> for ProposalDisposition {
    fn from(state: ProtectedQueryStatus) -> Self {
        match state {
            ProtectedQueryStatus::Submitted => Self::Submitted,
            ProtectedQueryStatus::Started => Self::Started,
            ProtectedQueryStatus::Cancelling => Self::Cancelling,
            ProtectedQueryStatus::Success => Self::Success,
            ProtectedQueryStatus::Failed => Self::Failed,
            ProtectedQueryStatus::Cancelled => Self::Cancelled,
            ProtectedQueryStatus::TimedOut => Self::TimedOut,
            ProtectedQueryStatus::Partial => Self::Partial,
            ProtectedQueryStatus::AccessLost => Self::AccessLost,
            ProtectedQueryStatus::ProviderUnknown => Self::ProviderUnknown,
            ProtectedQueryStatus::Tampered => Self::Tampered,
            ProtectedQueryStatus::Revoked => Self::Revoked,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsCleanRoomsResult {
    pub service_id: String,
    pub consumer_id: String,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub mission: crate::model::MissionProjection,
    pub project: crate::model::ProjectProjection,
    pub work_product: crate::model::WorkProductProjection,
    pub state: ProtectedQueryStatus,
    pub disposition: ProposalDisposition,
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

impl MissionAwsCleanRoomsResult {
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedAwsCleanRoomsResult {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub state: ProtectedQueryStatus,
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

impl RecordedAwsCleanRoomsResult {
    fn new(
        idempotency_key_digest: Digest,
        proposal: &AwsCleanRoomsQueryResultProposal,
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
            recording_digest: Digest::from_text("unsealed-aws-clean-rooms-recording"),
        };
        result.recording_digest = result.calculate_digest();
        result
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-clean-rooms-recording/v1",
            &[
                (
                    "idempotency",
                    self.idempotency_key_digest.as_str().to_owned(),
                ),
                ("proposal", self.proposal_digest.as_str().to_owned()),
                ("state", self.state.as_str().to_owned()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
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
            return Err(AwsCleanRoomsQueryResultError::TamperedEvidence);
        }
        Ok(())
    }
}

/// Consumer scoped to one exact AWS Clean Rooms registration and Mission fence.
pub struct MissionAwsCleanRoomsConsumer {
    scope: AwsCleanRoomsQueryResultScope,
    registration: AwsCleanRoomsQueryResultRegistration,
    records: BTreeMap<Digest, RecordedAwsCleanRoomsResult>,
}

impl fmt::Debug for MissionAwsCleanRoomsConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAwsCleanRoomsConsumer")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest(),
            )
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionAwsCleanRoomsConsumer {
    pub fn new(
        scope: AwsCleanRoomsQueryResultScope,
        registration: AwsCleanRoomsQueryResultRegistration,
    ) -> Result<Self> {
        registration.validate()?;
        if !registration.is_active() {
            return Err(AwsCleanRoomsQueryResultError::RegistrationInactive);
        }
        if registration.scope_digest() != &scope.digest() {
            return Err(AwsCleanRoomsQueryResultError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    pub fn registration(&self) -> &AwsCleanRoomsQueryResultRegistration {
        &self.registration
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn consume(
        &self,
        proposal: &AwsCleanRoomsQueryResultProposal,
    ) -> Result<MissionAwsCleanRoomsResult> {
        proposal.validate_integrity()?;
        if !self.registration.is_active() {
            return Err(AwsCleanRoomsQueryResultError::RegistrationInactive);
        }
        if proposal.service_id != SERVICE_ID
            || proposal.consumer_id != CONSUMER_ID
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
            || proposal.account_digest != self.scope.account().digest()
            || proposal.region_digest != self.scope.region().digest()
            || proposal.collaboration_digest != self.scope.collaboration().digest()
            || proposal.membership_digest != self.scope.membership().digest()
            || proposal.analysis_template_digest != self.scope.analysis_template().digest()
            || proposal.protected_query_digest != self.scope.protected_query().digest()
            || proposal.privacy_budget_digest != self.scope.privacy_budget().digest()
            || proposal.mission.id_digest != self.scope.mission().digest()
            || proposal.project.id_digest != self.scope.project().digest()
            || proposal.work_product.id_digest != self.scope.work_product().digest()
        {
            return Err(AwsCleanRoomsQueryResultError::ScopeMismatch);
        }
        Ok(MissionAwsCleanRoomsResult {
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
        proposal: &AwsCleanRoomsQueryResultProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<RecordedAwsCleanRoomsResult> {
        let _ = self.consume(proposal)?;
        let key = idempotency_key.as_ref();
        if key.is_empty() || key.len() > crate::MAX_IDENTIFIER_BYTES {
            return Err(AwsCleanRoomsQueryResultError::InvalidRequest);
        }
        let key_digest = Digest::from_text(key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(AwsCleanRoomsQueryResultError::RecordingConflict);
            }
            let replay = RecordedAwsCleanRoomsResult::new(key_digest.clone(), proposal, true);
            return Ok(replay);
        }
        if !self.registration.is_active() {
            return Err(AwsCleanRoomsQueryResultError::RegistrationInactive);
        }
        let result = RecordedAwsCleanRoomsResult::new(key_digest.clone(), proposal, false);
        self.records.insert(key_digest, result.clone());
        Ok(result)
    }
}
