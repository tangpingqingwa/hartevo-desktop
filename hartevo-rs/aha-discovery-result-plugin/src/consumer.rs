//! Mission-scoped proposal consumption and idempotent recording.

use std::{collections::BTreeMap, fmt};

use serde::Serialize;

use crate::model::{
    AhaDiscoveryResultError, AhaDiscoveryScope, Digest, EvidenceDigests, InsightState,
    RedactionSummary,
};
use crate::provider::TransportProvenance;
use crate::service::{AhaDiscoveryRegistration, AhaDiscoveryResultProposal};
use crate::{AHA_DISCOVERY_RESULT_CONSUMER_ID, AHA_DISCOVERY_RESULT_SERVICE_ID};

/// Consumer-facing disposition mirrors the bounded result state without adding authority.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    Present,
    Partial,
    Archived,
    AccessLost,
    ProviderUnknown,
    Stale,
    Tampered,
    Revoked,
}

impl From<InsightState> for ProposalDisposition {
    fn from(state: InsightState) -> Self {
        match state {
            InsightState::Present => Self::Present,
            InsightState::Partial => Self::Partial,
            InsightState::Archived => Self::Archived,
            InsightState::AccessLost => Self::AccessLost,
            InsightState::ProviderUnknown => Self::ProviderUnknown,
            InsightState::Stale => Self::Stale,
            InsightState::Tampered => Self::Tampered,
            InsightState::Revoked => Self::Revoked,
        }
    }
}

/// Mission result is always review-only and cannot be adopted as Truth or Work Product.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAhaDiscoveryResult {
    pub service_id: String,
    pub consumer_id: String,
    pub proposal_digest: Digest,
    pub scope: AhaDiscoveryScope,
    pub state: InsightState,
    pub disposition: ProposalDisposition,
    pub evidence: EvidenceDigests,
    pub provenance: TransportProvenance,
    pub redaction: RedactionSummary,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

impl MissionAhaDiscoveryResult {
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

/// Deterministic idempotent recording of a redacted proposal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedAhaDiscoveryResult {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub state: InsightState,
    pub disposition: ProposalDisposition,
    pub evidence: EvidenceDigests,
    pub provenance: TransportProvenance,
    pub redaction: RedactionSummary,
    pub replayed: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub recording_digest: Digest,
}

impl RecordedAhaDiscoveryResult {
    fn new(
        idempotency_key_digest: Digest,
        proposal: &AhaDiscoveryResultProposal,
        replayed: bool,
    ) -> Self {
        let mut result = Self {
            idempotency_key_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            state: proposal.state,
            disposition: proposal.state.into(),
            evidence: proposal.evidence.clone(),
            provenance: proposal.provenance,
            redaction: proposal.redaction.clone(),
            replayed,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            recording_digest: Digest::from_text("unsealed-aha-recording"),
        };
        result.recording_digest = result.calculate_digest();
        result
    }

    pub fn validate_integrity(&self) -> Result<(), AhaDiscoveryResultError> {
        self.evidence.validate()?;
        self.redaction.validate()?;
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.recording_digest != self.calculate_digest()
        {
            return Err(AhaDiscoveryResultError::TamperedEvidence);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aha-discovery-recording/v1",
            &[
                (
                    "idempotency",
                    self.idempotency_key_digest.as_str().to_owned(),
                ),
                ("proposal", self.proposal_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("state", self.state.as_str().to_owned()),
                ("evidence", self.evidence.digest().as_str().to_owned()),
                ("provenance", self.provenance.as_str().to_owned()),
                ("redaction", self.redaction.digest().as_str().to_owned()),
                ("replayed", self.replayed.to_string()),
                ("connected", self.connected.to_string()),
                ("native", self.native.to_string()),
                ("first_party", self.first_party.to_string()),
                ("provider_receipt", self.provider_receipt.to_string()),
                ("outcome_adopted", self.outcome_adopted.to_string()),
                (
                    "work_product_adopted",
                    self.work_product_adopted.to_string(),
                ),
            ],
        )
    }
}

/// Consumer scoped to one exact Project/Mission/Work Product registration.
pub struct MissionAhaDiscoveryConsumer {
    scope: AhaDiscoveryScope,
    registration: AhaDiscoveryRegistration,
    records: BTreeMap<Digest, RecordedAhaDiscoveryResult>,
}

impl fmt::Debug for MissionAhaDiscoveryConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAhaDiscoveryConsumer")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest(),
            )
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionAhaDiscoveryConsumer {
    pub fn new(
        scope: AhaDiscoveryScope,
        registration: AhaDiscoveryRegistration,
    ) -> Result<Self, AhaDiscoveryResultError> {
        registration.validate()?;
        if !registration.is_active() {
            return Err(AhaDiscoveryResultError::RegistrationInactive);
        }
        if registration.scope_digest() != &scope.digest() {
            return Err(AhaDiscoveryResultError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    pub fn registration(&self) -> &AhaDiscoveryRegistration {
        &self.registration
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn consume(
        &self,
        proposal: &AhaDiscoveryResultProposal,
    ) -> Result<MissionAhaDiscoveryResult, AhaDiscoveryResultError> {
        proposal.validate_integrity()?;
        if !self.registration.is_active() {
            return Err(AhaDiscoveryResultError::RegistrationInactive);
        }
        if proposal.service_id != AHA_DISCOVERY_RESULT_SERVICE_ID
            || proposal.consumer_id != AHA_DISCOVERY_RESULT_CONSUMER_ID
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
            || proposal.page.scope != self.scope
            || proposal.evidence.scope_digest != self.scope.digest()
        {
            return Err(AhaDiscoveryResultError::ScopeMismatch);
        }
        Ok(MissionAhaDiscoveryResult {
            service_id: AHA_DISCOVERY_RESULT_SERVICE_ID.to_owned(),
            consumer_id: AHA_DISCOVERY_RESULT_CONSUMER_ID.to_owned(),
            proposal_digest: proposal.proposal_digest.clone(),
            scope: self.scope.clone(),
            state: proposal.state,
            disposition: proposal.state.into(),
            evidence: proposal.evidence.clone(),
            provenance: proposal.provenance,
            redaction: proposal.redaction.clone(),
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
        proposal: &AhaDiscoveryResultProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<RecordedAhaDiscoveryResult, AhaDiscoveryResultError> {
        let _ = self.consume(proposal)?;
        let key = idempotency_key.as_ref();
        if !crate::model::valid_identifier(key) {
            return Err(AhaDiscoveryResultError::InvalidIdempotencyKey);
        }
        let key_digest = Digest::from_text(key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(AhaDiscoveryResultError::RecordingConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            replay.recording_digest = replay.calculate_digest();
            replay.validate_integrity()?;
            return Ok(replay);
        }
        let result = RecordedAhaDiscoveryResult::new(key_digest.clone(), proposal, false);
        self.records.insert(key_digest, result.clone());
        Ok(result)
    }
}
