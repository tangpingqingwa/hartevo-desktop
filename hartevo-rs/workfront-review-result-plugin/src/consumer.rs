//! Mission-scoped proposal consumption and idempotent recording.

use std::{collections::BTreeMap, fmt};

use serde::Serialize;

use crate::error::{Result, WorkfrontReviewResultError};
use crate::model::{
    Digest, EvidenceDigests, EvidenceState, HostProjectProjection, MissionProjection,
    TransportProvenance, WorkProductProjection, WorkfrontReviewScope,
};
use crate::service::{WorkfrontReviewProposal, WorkfrontReviewRegistration};
use crate::{CONSUMER_ID, SERVICE_ID};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    Pending,
    InReview,
    Approved,
    Rejected,
    ChangesRequested,
    Expired,
    Partial,
    AccessLost,
    ProviderUnknown,
    Tampered,
    Revoked,
}

impl From<EvidenceState> for ProposalDisposition {
    fn from(value: EvidenceState) -> Self {
        match value {
            EvidenceState::Pending => Self::Pending,
            EvidenceState::InReview => Self::InReview,
            EvidenceState::Approved => Self::Approved,
            EvidenceState::Rejected => Self::Rejected,
            EvidenceState::ChangesRequested => Self::ChangesRequested,
            EvidenceState::Expired => Self::Expired,
            EvidenceState::Partial => Self::Partial,
            EvidenceState::AccessLost => Self::AccessLost,
            EvidenceState::ProviderUnknown => Self::ProviderUnknown,
            EvidenceState::Tampered => Self::Tampered,
            EvidenceState::Revoked => Self::Revoked,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionWorkfrontReviewResult {
    pub service_id: String,
    pub consumer_id: String,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub mission: MissionProjection,
    pub project: HostProjectProjection,
    pub work_product: WorkProductProjection,
    pub state: EvidenceState,
    pub disposition: ProposalDisposition,
    pub evidence: EvidenceDigests,
    pub provenance: TransportProvenance,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub approval_effect: bool,
    pub document_bytes_retained: bool,
    pub reviewer_pii_retained: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

impl MissionWorkfrontReviewResult {
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedWorkfrontReviewResult {
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
    pub approval_effect: bool,
    pub document_bytes_retained: bool,
    pub reviewer_pii_retained: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub recording_digest: Digest,
}

impl RecordedWorkfrontReviewResult {
    fn new(
        idempotency_key_digest: Digest,
        proposal: &WorkfrontReviewProposal,
        replayed: bool,
    ) -> Self {
        let mut value = Self {
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
            approval_effect: false,
            document_bytes_retained: false,
            reviewer_pii_retained: false,
            outcome_adopted: false,
            work_product_adopted: false,
            recording_digest: Digest::from_text("unsealed-workfront-recording"),
        };
        value.recording_digest = value.calculate_digest();
        value
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "workfront-recording/v1",
            &[
                (
                    "idempotency",
                    self.idempotency_key_digest.as_str().to_owned(),
                ),
                ("proposal", self.proposal_digest.as_str().to_owned()),
                ("state", format!("{:?}", self.state)),
                ("provenance", self.provenance.as_str().to_owned()),
                ("replayed", self.replayed.to_string()),
            ],
        )
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.approval_effect
            || self.document_bytes_retained
            || self.reviewer_pii_retained
            || self.outcome_adopted
            || self.work_product_adopted
            || self.recording_digest != self.calculate_digest()
        {
            return Err(WorkfrontReviewResultError::TamperedEvidence);
        }
        Ok(())
    }
}

/// Consumer bound to exactly one registration and Mission/Project/Work
/// Product generation. It has no approval or adoption authority.
pub struct MissionWorkfrontReviewConsumer {
    scope: WorkfrontReviewScope,
    registration: WorkfrontReviewRegistration,
    records: BTreeMap<Digest, RecordedWorkfrontReviewResult>,
}

impl fmt::Debug for MissionWorkfrontReviewConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionWorkfrontReviewConsumer")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest(),
            )
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionWorkfrontReviewConsumer {
    pub fn new(
        scope: WorkfrontReviewScope,
        registration: WorkfrontReviewRegistration,
    ) -> Result<Self> {
        registration.validate()?;
        if !registration.is_active() {
            return Err(WorkfrontReviewResultError::RegistrationInactive);
        }
        if registration.scope_digest() != &scope.digest() {
            return Err(WorkfrontReviewResultError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    pub fn registration(&self) -> &WorkfrontReviewRegistration {
        &self.registration
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn consume(
        &self,
        proposal: &WorkfrontReviewProposal,
    ) -> Result<MissionWorkfrontReviewResult> {
        proposal.validate_integrity()?;
        if !self.registration.is_active() {
            return Err(WorkfrontReviewResultError::RegistrationInactive);
        }
        if proposal.service_id != SERVICE_ID
            || proposal.consumer_id != CONSUMER_ID
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
            || proposal.mission.id_digest != *self.scope.mission().id_digest()
            || proposal.mission.revision != self.scope.mission().revision()
            || proposal.project.id_digest != *self.scope.host_project().id_digest()
            || proposal.project.revision != self.scope.host_project().revision()
            || proposal.work_product.id_digest != *self.scope.work_product().id_digest()
            || proposal.work_product.revision != self.scope.work_product().revision()
        {
            return Err(WorkfrontReviewResultError::ScopeMismatch);
        }
        Ok(MissionWorkfrontReviewResult {
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
            provenance: proposal.provenance,
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            approval_effect: false,
            document_bytes_retained: false,
            reviewer_pii_retained: false,
            outcome_adopted: false,
            work_product_adopted: false,
        })
    }

    pub fn record(
        &mut self,
        proposal: &WorkfrontReviewProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<RecordedWorkfrontReviewResult> {
        proposal.validate_integrity()?;
        let key = idempotency_key.as_ref();
        if key.is_empty() || key.len() > crate::MAX_IDENTIFIER_BYTES {
            return Err(WorkfrontReviewResultError::InvalidText {
                field: "idempotency key",
            });
        }
        let idempotency_key_digest = Digest::from_text(key);
        if let Some(existing) = self.records.get(&idempotency_key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(WorkfrontReviewResultError::ReplayConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            replay.recording_digest = replay.calculate_digest();
            return Ok(replay);
        }
        let value =
            RecordedWorkfrontReviewResult::new(idempotency_key_digest.clone(), proposal, false);
        value.validate_integrity()?;
        self.records.insert(idempotency_key_digest, value.clone());
        Ok(value)
    }
}
