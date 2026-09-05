use std::{collections::BTreeMap, fmt};

use serde::Serialize;
use thiserror::Error;

use crate::model::{
    Digest, SnowplowEvidenceState, SnowplowModelError, SnowplowRegistration,
    SnowplowTrackingPlanEvidence, SnowplowTrackingPlanScope, SnowplowTransportProvenance,
    canonical_digest,
};
use crate::service::SnowplowTrackingPlanProposal;
use crate::{CONSUMER_ID, SERVICE_ID};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MissionSnowplowConsumerError {
    #[error("Snowplow registration is revoked or drifted")]
    RegistrationRevoked,
    #[error("Snowplow Mission scope does not match the proposal")]
    ScopeMismatch,
    #[error("Snowplow proposal integrity verification failed")]
    EvidenceMismatch,
    #[error("Snowplow observation replay conflicts with an existing record")]
    ReplayConflict,
    #[error("Snowplow idempotency key is invalid")]
    InvalidIdempotencyKey,
    #[error(transparent)]
    Model(#[from] SnowplowModelError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionSnowplowDisposition {
    Draft,
    Active,
    Archived,
    Missing,
    Partial,
    AccessLoss,
    ProviderUnknown,
    Tamper,
    Stale,
    Revoked,
}

impl From<SnowplowEvidenceState> for MissionSnowplowDisposition {
    fn from(state: SnowplowEvidenceState) -> Self {
        match state {
            SnowplowEvidenceState::Draft => Self::Draft,
            SnowplowEvidenceState::Active => Self::Active,
            SnowplowEvidenceState::Archived => Self::Archived,
            SnowplowEvidenceState::Missing => Self::Missing,
            SnowplowEvidenceState::Partial => Self::Partial,
            SnowplowEvidenceState::AccessLoss => Self::AccessLoss,
            SnowplowEvidenceState::ProviderUnknown => Self::ProviderUnknown,
            SnowplowEvidenceState::Tamper => Self::Tamper,
            SnowplowEvidenceState::Stale => Self::Stale,
            SnowplowEvidenceState::Revoked => Self::Revoked,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionSnowplowTrackingPlanResult {
    pub service_id: String,
    pub consumer_id: String,
    pub scope_digest: Digest,
    pub proposal_digest: Digest,
    pub source_evidence_digest: Digest,
    pub state: SnowplowEvidenceState,
    pub disposition: MissionSnowplowDisposition,
    pub evidence: SnowplowTrackingPlanEvidence,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

impl MissionSnowplowTrackingPlanResult {
    #[must_use]
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedSnowplowTrackingPlanResult {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub state: SnowplowEvidenceState,
    pub disposition: MissionSnowplowDisposition,
    pub provenance: SnowplowTransportProvenance,
    pub replayed: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub recording_digest: Digest,
}

impl RecordedSnowplowTrackingPlanResult {
    fn new(
        idempotency_key_digest: Digest,
        proposal: &SnowplowTrackingPlanProposal,
        replayed: bool,
    ) -> Self {
        let mut result = Self {
            idempotency_key_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            state: proposal.state,
            disposition: proposal.state.into(),
            provenance: proposal.evidence.provenance,
            replayed,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            recording_digest: String::new(),
        };
        result.recording_digest = recording_digest(&result);
        result
    }

    pub fn validate_integrity(&self) -> Result<(), MissionSnowplowConsumerError> {
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.recording_digest != recording_digest(self)
        {
            return Err(MissionSnowplowConsumerError::EvidenceMismatch);
        }
        Ok(())
    }
}

/// Mission projection consumer. It can consume and record a proposal, but it
/// cannot convert provider evidence into Truth, Work Product, Receipt, or
/// Outcome authority.
pub struct MissionSnowplowTrackingPlanConsumer {
    scope: SnowplowTrackingPlanScope,
    registration: SnowplowRegistration,
    records: BTreeMap<Digest, RecordedSnowplowTrackingPlanResult>,
}

impl fmt::Debug for MissionSnowplowTrackingPlanConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionSnowplowTrackingPlanConsumer")
            .field("scope_digest", self.scope.digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest,
            )
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionSnowplowTrackingPlanConsumer {
    pub fn new(
        scope: SnowplowTrackingPlanScope,
        registration: SnowplowRegistration,
    ) -> Result<Self, MissionSnowplowConsumerError> {
        registration
            .validate_for_consumer(&scope, &registration.provider_digest)
            .map_err(|_| MissionSnowplowConsumerError::RegistrationRevoked)?;
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    #[must_use]
    pub fn registration(&self) -> &SnowplowRegistration {
        &self.registration
    }

    #[must_use]
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn consume(
        &self,
        proposal: &SnowplowTrackingPlanProposal,
    ) -> Result<MissionSnowplowTrackingPlanResult, MissionSnowplowConsumerError> {
        proposal
            .validate_integrity()
            .map_err(|_| MissionSnowplowConsumerError::EvidenceMismatch)?;
        if self.registration.state != crate::SnowplowRegistrationState::Active {
            return Err(MissionSnowplowConsumerError::RegistrationRevoked);
        }
        if proposal.service_id != SERVICE_ID
            || proposal.consumer_id != CONSUMER_ID
            || proposal.scope_digest != *self.scope.digest()
            || proposal.registration_digest != self.registration.registration_digest
            || proposal.permission_digest != self.scope.permissions().digest()
            || proposal.provider_digest != self.registration.provider_digest
            || proposal.contract_digest != crate::contract_digest()
        {
            return Err(MissionSnowplowConsumerError::ScopeMismatch);
        }
        Ok(MissionSnowplowTrackingPlanResult {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            scope_digest: proposal.scope_digest.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            source_evidence_digest: proposal.source_evidence_digest.clone(),
            state: proposal.state,
            disposition: proposal.state.into(),
            evidence: proposal.evidence.clone(),
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
        proposal: &SnowplowTrackingPlanProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<RecordedSnowplowTrackingPlanResult, MissionSnowplowConsumerError> {
        let _ = self.consume(proposal)?;
        let idempotency_key = idempotency_key.as_ref();
        if idempotency_key.is_empty()
            || idempotency_key.len() > crate::model::MAX_IDENTIFIER_BYTES
            || idempotency_key.chars().any(char::is_control)
        {
            return Err(MissionSnowplowConsumerError::InvalidIdempotencyKey);
        }
        let key_digest = sha256_digest(idempotency_key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(MissionSnowplowConsumerError::ReplayConflict);
            }
            let replay = RecordedSnowplowTrackingPlanResult::new(key_digest, proposal, true);
            replay.validate_integrity()?;
            return Ok(replay);
        }
        let result = RecordedSnowplowTrackingPlanResult::new(key_digest.clone(), proposal, false);
        result.validate_integrity()?;
        self.records.insert(key_digest, result.clone());
        Ok(result)
    }
}

fn sha256_digest(value: impl AsRef<[u8]>) -> Digest {
    crate::sha256_digest(value.as_ref())
}

fn recording_digest(result: &RecordedSnowplowTrackingPlanResult) -> Digest {
    canonical_digest(&(
        "snowplow-mission-recording/v1",
        &result.idempotency_key_digest,
        &result.proposal_digest,
        result.state,
        &result.provenance,
        result.replayed,
    ))
}

pub type MissionSnowplowConsumer = MissionSnowplowTrackingPlanConsumer;
