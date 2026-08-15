use std::{collections::BTreeMap, fmt};

use serde::Serialize;

use crate::error::{Result, SodaQualityResultError};
use crate::model::{
    Digest, SodaCostReceipt, SodaEvidenceDigests, SodaEvidenceState, SodaQualityResultProposal,
    SodaQualityScope, SodaRecommendation, SodaRegistration, SodaRequestReceipt,
    TransportProvenance,
};
use crate::{CONSUMER_ID, SERVICE_ID};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionSodaQualityResult {
    pub service_id: String,
    pub consumer_id: String,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub state: SodaEvidenceState,
    pub recommendation: SodaRecommendation,
    pub evidence: SodaEvidenceDigests,
    pub request_receipts: Vec<SodaRequestReceipt>,
    pub cost_receipts: Vec<SodaCostReceipt>,
    pub provenance: TransportProvenance,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

impl MissionSodaQualityResult {
    #[must_use]
    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.scope_digest.validate()?;
        self.proposal_digest.validate()?;
        self.evidence.validate()?;
        for receipt in &self.request_receipts {
            receipt.validate()?;
        }
        for receipt in &self.cost_receipts {
            receipt.validate()?;
        }
        if self.service_id != SERVICE_ID
            || self.consumer_id != CONSUMER_ID
            || !self.review_only
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
        {
            return Err(SodaQualityResultError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionSodaQualityRecord {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub registration_digest: Digest,
    pub state: SodaEvidenceState,
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

impl MissionSodaQualityRecord {
    fn new(
        idempotency_key_digest: Digest,
        proposal: &SodaQualityResultProposal,
        replayed: bool,
    ) -> Self {
        let mut record = Self {
            idempotency_key_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            state: proposal.state(),
            provenance: proposal.evidence.provenance,
            replayed,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            recording_digest: Digest::from_text("unsealed-soda-mission-recording"),
        };
        record.recording_digest = record.calculate_digest();
        record
    }

    #[must_use]
    pub fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "soda-mission-recording/v1",
            &[
                (
                    "idempotency",
                    self.idempotency_key_digest.as_str().to_owned(),
                ),
                ("proposal", self.proposal_digest.as_str().to_owned()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("state", format!("{:?}", self.state)),
                ("provenance", self.provenance.as_str().to_owned()),
                ("replayed", self.replayed.to_string()),
            ],
        )
    }

    pub fn validate_integrity(&self) -> Result<()> {
        for digest in [
            &self.idempotency_key_digest,
            &self.proposal_digest,
            &self.registration_digest,
            &self.recording_digest,
        ] {
            digest.validate()?;
        }
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.recording_digest != self.calculate_digest()
        {
            return Err(SodaQualityResultError::TamperedEvidence);
        }
        Ok(())
    }

    #[must_use]
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

pub struct MissionSodaQualityConsumer {
    scope: SodaQualityScope,
    registration: SodaRegistration,
    records: BTreeMap<Digest, MissionSodaQualityRecord>,
}

impl fmt::Debug for MissionSodaQualityConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionSodaQualityConsumer")
            .field("scope_digest", &self.scope.digest())
            .field("registration_digest", &self.registration.digest())
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionSodaQualityConsumer {
    pub fn new(scope: SodaQualityScope, registration: SodaRegistration) -> Result<Self> {
        if !registration.is_active() {
            return Err(SodaQualityResultError::RegistrationInactive);
        }
        if registration.scope_digest != *scope.digest() {
            return Err(SodaQualityResultError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn registration(&self) -> &SodaRegistration {
        &self.registration
    }

    #[must_use]
    pub fn scope(&self) -> &SodaQualityScope {
        &self.scope
    }

    #[must_use]
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn consume(
        &self,
        proposal: &SodaQualityResultProposal,
    ) -> Result<MissionSodaQualityResult> {
        proposal.validate_integrity()?;
        if !self.registration.is_active() {
            return Err(SodaQualityResultError::RegistrationInactive);
        }
        if proposal.registration_digest != *self.registration.digest()
            || proposal.scope.digest() != self.scope.digest()
        {
            return Err(SodaQualityResultError::ScopeMismatch);
        }
        let result = MissionSodaQualityResult {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.scope.digest().clone(),
            state: proposal.state(),
            recommendation: proposal.recommendation.clone(),
            evidence: proposal.evidence.digests.clone(),
            request_receipts: proposal.evidence.request_receipts.clone(),
            cost_receipts: proposal.evidence.cost_receipts.clone(),
            provenance: proposal.evidence.provenance,
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
        };
        result.validate_integrity()?;
        Ok(result)
    }

    pub fn record(
        &mut self,
        proposal: &SodaQualityResultProposal,
        idempotency_key: impl Into<String>,
    ) -> Result<MissionSodaQualityRecord> {
        let key = Digest::from_parts(
            "soda-idempotency-key/v1",
            &[
                ("key", idempotency_key.into()),
                ("scope", self.scope.digest().as_str().to_owned()),
            ],
        );
        if proposal.evidence.idempotency_key_digest != key {
            return Err(SodaQualityResultError::ScopeMismatch);
        }
        let _ = self.consume(proposal)?;
        if let Some(existing) = self.records.get(&key) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(SodaQualityResultError::RecordingConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            replay.recording_digest = replay.calculate_digest();
            return Ok(replay);
        }
        let record = MissionSodaQualityRecord::new(key.clone(), proposal, false);
        record.validate_integrity()?;
        self.records.insert(key, record.clone());
        Ok(record)
    }

    pub fn revoke(&mut self) -> Result<crate::RegistrationTransitionReceipt> {
        self.registration.revoke()
    }

    pub fn restore(&mut self) -> Result<crate::RegistrationTransitionReceipt> {
        self.registration.restore()
    }
}

pub type MissionSodaQualityResultState = SodaEvidenceState;
pub type RecordedMissionSodaQualityResult = MissionSodaQualityRecord;
