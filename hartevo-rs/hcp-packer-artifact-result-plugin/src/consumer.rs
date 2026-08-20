use std::{collections::BTreeMap, fmt};

use serde::Serialize;

use crate::error::{HcpPackerArtifactResultError, Result};
use crate::model::{Digest, HcpPackerArtifactScope, HcpPackerEvidenceState, TransportProvenance};
use crate::service::{
    HcpPackerArtifactRecordReceipt, HcpPackerArtifactResultProposal,
    HcpPackerArtifactResultRegistration, RegistrationStatus,
};
use crate::{CONSUMER_ID, SERVICE_ID};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    Ready,
    Running,
    Incomplete,
    Cancelled,
    Failed,
    Revoked,
    Partial,
    Stale,
    Truncated,
    PaginationReplay,
    AccessLoss,
    ProviderUnknown,
    Tampered,
    RegistrationRevoked,
}

impl From<HcpPackerEvidenceState> for ProposalDisposition {
    fn from(state: HcpPackerEvidenceState) -> Self {
        match state {
            HcpPackerEvidenceState::Ready => Self::Ready,
            HcpPackerEvidenceState::Running => Self::Running,
            HcpPackerEvidenceState::Incomplete => Self::Incomplete,
            HcpPackerEvidenceState::Cancelled => Self::Cancelled,
            HcpPackerEvidenceState::Failed => Self::Failed,
            HcpPackerEvidenceState::Revoked => Self::Revoked,
            HcpPackerEvidenceState::Partial => Self::Partial,
            HcpPackerEvidenceState::Stale => Self::Stale,
            HcpPackerEvidenceState::Truncated => Self::Truncated,
            HcpPackerEvidenceState::PaginationReplay => Self::PaginationReplay,
            HcpPackerEvidenceState::AccessLoss => Self::AccessLoss,
            HcpPackerEvidenceState::ProviderUnknown => Self::ProviderUnknown,
            HcpPackerEvidenceState::Tampered => Self::Tampered,
            HcpPackerEvidenceState::RegistrationRevoked => Self::RegistrationRevoked,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionHcpPackerArtifactResult {
    pub service_id: String,
    pub consumer_id: String,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub state: HcpPackerEvidenceState,
    pub disposition: ProposalDisposition,
    pub evidence: Option<crate::model::HcpPackerArtifactEvidence>,
    pub failure: Option<crate::model::FailureEvidence>,
    pub provenance: TransportProvenance,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub truth_authority: bool,
    pub consent_authority: bool,
    pub effect_authority: bool,
    pub receipt_authority: bool,
    pub verification_authority: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

impl MissionHcpPackerArtifactResult {
    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub const fn is_review_only(&self) -> bool {
        true
    }
}

pub type MissionHcpPackerArtifactResultEnvelope = MissionHcpPackerArtifactResult;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedHcpPackerArtifactResult {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub state: HcpPackerEvidenceState,
    pub disposition: ProposalDisposition,
    pub provenance: TransportProvenance,
    pub replayed: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub durable_provider_receipt: bool,
    pub truth_authority: bool,
    pub consent_authority: bool,
    pub effect_authority: bool,
    pub receipt_authority: bool,
    pub verification_authority: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub recording_digest: Digest,
}

impl RecordedHcpPackerArtifactResult {
    fn from_receipt(receipt: HcpPackerArtifactRecordReceipt) -> Self {
        Self {
            idempotency_key_digest: receipt.idempotency_key_digest,
            proposal_digest: receipt.proposal_digest,
            state: receipt.state,
            disposition: receipt.state.into(),
            provenance: receipt.provenance,
            replayed: receipt.replayed,
            connected: receipt.connected,
            native: receipt.native,
            first_party: receipt.first_party,
            provider_receipt: receipt.provider_receipt,
            durable_provider_receipt: receipt.durable_provider_receipt,
            truth_authority: false,
            consent_authority: false,
            effect_authority: false,
            receipt_authority: false,
            verification_authority: false,
            outcome_adopted: receipt.outcome_adopted,
            work_product_adopted: receipt.work_product_adopted,
            recording_digest: receipt.recording_digest,
        }
    }

    pub fn validate_integrity(&self) -> Result<()> {
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.durable_provider_receipt
            || self.truth_authority
            || self.consent_authority
            || self.effect_authority
            || self.receipt_authority
            || self.verification_authority
            || self.outcome_adopted
            || self.work_product_adopted
            || self.recording_digest != self.compute_recording_digest()
        {
            return Err(HcpPackerArtifactResultError::TamperedEvidence);
        }
        Ok(())
    }

    fn compute_recording_digest(&self) -> Digest {
        Digest::from_parts(
            "hcp-packer-local-recording/v1",
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
}

pub struct MissionHcpPackerArtifactConsumer {
    scope: HcpPackerArtifactScope,
    registration: HcpPackerArtifactResultRegistration,
    records: BTreeMap<Digest, RecordedHcpPackerArtifactResult>,
}

impl fmt::Debug for MissionHcpPackerArtifactConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionHcpPackerArtifactConsumer")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest(),
            )
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionHcpPackerArtifactConsumer {
    pub fn new(
        scope: HcpPackerArtifactScope,
        registration: HcpPackerArtifactResultRegistration,
    ) -> Result<Self> {
        registration.validate()?;
        if !registration.is_active() {
            return Err(HcpPackerArtifactResultError::RegistrationInactive);
        }
        if registration.scope_digest() != &scope.digest() {
            return Err(HcpPackerArtifactResultError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    pub fn scope(&self) -> &HcpPackerArtifactScope {
        &self.scope
    }

    pub fn registration(&self) -> &HcpPackerArtifactResultRegistration {
        &self.registration
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn revoke_registration(&mut self) -> Result<()> {
        self.registration.revoke().map(|_| ())
    }

    pub fn consume(
        &self,
        proposal: &HcpPackerArtifactResultProposal,
    ) -> Result<MissionHcpPackerArtifactResult> {
        self.consume_for_mission_revision(proposal, self.scope.mission().revision().value())
    }

    pub fn consume_for_mission_revision(
        &self,
        proposal: &HcpPackerArtifactResultProposal,
        mission_revision: u64,
    ) -> Result<MissionHcpPackerArtifactResult> {
        if self.registration.status() != RegistrationStatus::Active {
            return Err(HcpPackerArtifactResultError::RegistrationInactive);
        }
        if mission_revision != self.scope.mission().revision().value() {
            return Err(HcpPackerArtifactResultError::StaleMissionRevision);
        }
        proposal.validate_integrity(&self.scope)?;
        if proposal.service_id != SERVICE_ID
            || proposal.consumer_id != CONSUMER_ID
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
        {
            return Err(HcpPackerArtifactResultError::ScopeMismatch);
        }
        Ok(MissionHcpPackerArtifactResult {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            state: proposal.state,
            disposition: proposal.state.into(),
            evidence: proposal.evidence.clone(),
            failure: proposal.failure.clone(),
            provenance: proposal.provenance,
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            truth_authority: false,
            consent_authority: false,
            effect_authority: false,
            receipt_authority: false,
            verification_authority: false,
            outcome_adopted: false,
            work_product_adopted: false,
        })
    }

    pub fn record(
        &mut self,
        proposal: &HcpPackerArtifactResultProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<RecordedHcpPackerArtifactResult> {
        let _ = self.consume(proposal)?;
        let idempotency_key = idempotency_key.as_ref();
        if idempotency_key.is_empty() || idempotency_key.len() > crate::MAX_IDENTIFIER_BYTES {
            return Err(HcpPackerArtifactResultError::InvalidRequest);
        }
        let key_digest = Digest::from_text(idempotency_key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(HcpPackerArtifactResultError::RecordingConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            replay.recording_digest = replay.compute_recording_digest();
            replay.validate_integrity()?;
            return Ok(replay);
        }
        let receipt = HcpPackerArtifactRecordReceipt::new(proposal, idempotency_key, false);
        let result = RecordedHcpPackerArtifactResult::from_receipt(receipt);
        result.validate_integrity()?;
        self.records.insert(key_digest, result.clone());
        Ok(result)
    }

    pub fn verify_evidence(
        &self,
        evidence: &crate::model::HcpPackerArtifactEvidence,
    ) -> Result<()> {
        if self.registration.status() != RegistrationStatus::Active {
            return Err(HcpPackerArtifactResultError::RegistrationInactive);
        }
        if evidence.digests.evidence_binding_digest != *self.registration.evidence_digest()
            || evidence.scope_digest != self.scope.digest()
        {
            return Err(HcpPackerArtifactResultError::EvidenceDrift);
        }
        evidence.validate_integrity(&self.scope)
    }
}

pub type MissionHcpPackerArtifactConsumerError = HcpPackerArtifactResultError;
pub type MissionHcpPackerConsumer = MissionHcpPackerArtifactConsumer;
