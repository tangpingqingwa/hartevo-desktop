//! Mission-scoped, review-only consumption and idempotent recording.

use std::{collections::BTreeMap, fmt};

use serde::Serialize;

use crate::error::{Result, SiftFraudResultError};
use crate::model::{
    Digest, RegistrationStatus, SiftFraudResultRegistration, SiftFraudResultScope,
    SiftFraudResultState,
};
use crate::service::{SiftFraudResultProposal, VerificationReport};
use crate::{CONSUMER_ID, SERVICE_ID};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionSiftFraudResult {
    pub service_id: String,
    pub consumer_id: String,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub proposal_digest: Digest,
    pub idempotency_digest: Digest,
    pub state: SiftFraudResultState,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub fraud_certainty: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub replayed: bool,
    pub recording_digest: Digest,
}

impl MissionSiftFraudResult {
    fn new(proposal: &SiftFraudResultProposal, replayed: bool) -> Self {
        let mut result = Self {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            scope_digest: proposal.scope_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            idempotency_digest: proposal.idempotency_digest.clone(),
            state: proposal.state,
            review_only: true,
            connected: false,
            native: false,
            fraud_certainty: false,
            outcome_adopted: false,
            work_product_adopted: false,
            replayed,
            recording_digest: Digest::from_text("unsealed-sift-recording"),
        };
        result.recording_digest = result.calculate_digest();
        result
    }

    pub fn validate_integrity(&self) -> Result<()> {
        for digest in [
            &self.scope_digest,
            &self.registration_digest,
            &self.proposal_digest,
            &self.idempotency_digest,
            &self.recording_digest,
        ] {
            digest.validate()?;
        }
        if self.service_id != SERVICE_ID
            || self.consumer_id != CONSUMER_ID
            || !self.review_only
            || self.connected
            || self.native
            || self.fraud_certainty
            || self.outcome_adopted
            || self.work_product_adopted
            || self.recording_digest != self.calculate_digest()
        {
            return Err(SiftFraudResultError::TamperedProposal);
        }
        Ok(())
    }

    pub const fn is_replayed(&self) -> bool {
        self.replayed
    }

    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "sift-mission-recording/v1",
            &[
                ("consumer", CONSUMER_ID.to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("proposal", self.proposal_digest.as_str().to_owned()),
                ("idempotency", self.idempotency_digest.as_str().to_owned()),
                ("state", format!("{:?}", self.state)),
                ("replayed", self.replayed.to_string()),
            ],
        )
    }
}

pub type RecordedSiftFraudResult = MissionSiftFraudResult;
pub type MissionSiftFraudConsumerError = SiftFraudResultError;
pub type ConsumerError = SiftFraudResultError;
pub type ProposalDisposition = SiftFraudResultState;

pub struct MissionSiftFraudConsumer {
    scope: SiftFraudResultScope,
    registration: SiftFraudResultRegistration,
    records: BTreeMap<Digest, MissionSiftFraudResult>,
}

impl fmt::Debug for MissionSiftFraudConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionSiftFraudConsumer")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest(),
            )
            .field("registration_status", &self.registration.status())
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionSiftFraudConsumer {
    pub fn new(
        scope: SiftFraudResultScope,
        registration: SiftFraudResultRegistration,
    ) -> Result<Self> {
        registration.validate()?;
        if registration.scope_digest() != &scope.digest() {
            return Err(SiftFraudResultError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    pub fn scope(&self) -> &SiftFraudResultScope {
        &self.scope
    }

    pub fn registration(&self) -> &SiftFraudResultRegistration {
        &self.registration
    }

    pub fn project(&self, proposal: &SiftFraudResultProposal) -> Result<MissionSiftFraudResult> {
        self.consume(proposal)
    }

    pub fn consume(&self, proposal: &SiftFraudResultProposal) -> Result<MissionSiftFraudResult> {
        self.validate_proposal(proposal)?;
        Ok(MissionSiftFraudResult::new(proposal, false))
    }

    pub fn record(
        &mut self,
        proposal: &SiftFraudResultProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<MissionSiftFraudResult> {
        self.validate_proposal(proposal)?;
        let idempotency_digest = Digest::from_parts(
            "sift-idempotency-key/v1",
            &[("key", idempotency_key.as_ref().to_owned())],
        );
        if idempotency_digest != proposal.idempotency_digest {
            return Err(SiftFraudResultError::RecordingConflict);
        }
        if let Some(existing) = self.records.get(&idempotency_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(SiftFraudResultError::RecordingConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            replay.recording_digest = replay.calculate_digest();
            return Ok(replay);
        }
        let recorded = MissionSiftFraudResult::new(proposal, false);
        self.records.insert(idempotency_digest, recorded.clone());
        Ok(recorded)
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn verify(&self, proposal: &SiftFraudResultProposal) -> VerificationReport {
        if self.validate_proposal(proposal).is_err() {
            // Consumer verification has no authority of its own; the explicit
            // fail-closed result is represented by a minimally populated report.
            return VerificationReport {
                valid: false,
                review_eligible: false,
                failures: Vec::new(),
                verification_digest: Digest::from_text("sift-consumer-verification-failed"),
            };
        }
        VerificationReport {
            valid: true,
            review_eligible: matches!(
                proposal.state,
                SiftFraudResultState::Allow
                    | SiftFraudResultState::Deny
                    | SiftFraudResultState::Review
                    | SiftFraudResultState::Unknown
            ),
            failures: Vec::new(),
            verification_digest: Digest::from_parts(
                "sift-consumer-verification/v1",
                &[("proposal", proposal.proposal_digest.as_str().to_owned())],
            ),
        }
    }

    fn validate_proposal(&self, proposal: &SiftFraudResultProposal) -> Result<()> {
        if !self.registration.is_active()
            || matches!(
                self.registration.status(),
                RegistrationStatus::Revoked | RegistrationStatus::Reversed
            )
        {
            return Err(SiftFraudResultError::RegistrationInactive);
        }
        proposal.validate_integrity()?;
        if proposal.service_id != SERVICE_ID
            || proposal.consumer_id != CONSUMER_ID
            || proposal.scope_digest != self.scope.digest()
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.evidence.scope_digest != self.scope.digest()
        {
            return Err(SiftFraudResultError::ScopeMismatch);
        }
        Ok(())
    }
}
