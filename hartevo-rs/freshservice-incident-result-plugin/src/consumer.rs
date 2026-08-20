//! Mission-scoped proposal consumption and redacted idempotent recording.

use std::{collections::BTreeMap, fmt};

use serde::Serialize;

use crate::error::{FreshserviceIncidentResultError, Result};
use crate::model::{Digest, FreshserviceIncidentResultScope, TransportProvenance};
use crate::service::{
    FreshserviceIncidentResultProposal, FreshserviceIncidentResultRegistration,
    FreshserviceResultState, ObservationFailure, RegistrationTransitionEvidence,
};
use crate::{CONSUMER_ID, MAX_IDENTIFIER_BYTES, SERVICE_ID};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    Complete,
    Denied,
    Partial,
    Stale,
    AccessLoss,
    RateLimited,
    ProviderUnknown,
    NotFound,
    Tampered,
    RegistrationRevoked,
}

impl From<FreshserviceResultState> for ProposalDisposition {
    fn from(state: FreshserviceResultState) -> Self {
        match state {
            FreshserviceResultState::Complete => Self::Complete,
            FreshserviceResultState::Denied => Self::Denied,
            FreshserviceResultState::Partial => Self::Partial,
            FreshserviceResultState::Stale => Self::Stale,
            FreshserviceResultState::AccessLoss => Self::AccessLoss,
            FreshserviceResultState::RateLimited => Self::RateLimited,
            FreshserviceResultState::ProviderUnknown => Self::ProviderUnknown,
            FreshserviceResultState::NotFound => Self::NotFound,
            FreshserviceResultState::Tampered => Self::Tampered,
            FreshserviceResultState::RegistrationRevoked => Self::RegistrationRevoked,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionFreshserviceIncidentResult {
    pub service_id: String,
    pub consumer_id: String,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub project: crate::model::ProjectProjection,
    pub mission: crate::model::MissionProjection,
    pub work_product: crate::model::WorkProductProjection,
    pub state: FreshserviceResultState,
    pub disposition: ProposalDisposition,
    pub evidence_digest: Digest,
    pub provenance: TransportProvenance,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub ticket_mutation: bool,
    pub raw_notes: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

impl MissionFreshserviceIncidentResult {
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedFreshserviceIncidentResult {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub state: FreshserviceResultState,
    pub disposition: ProposalDisposition,
    pub provenance: TransportProvenance,
    pub replayed: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub ticket_mutation: bool,
    pub raw_notes: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub recording_digest: Digest,
}

impl RecordedFreshserviceIncidentResult {
    fn new(
        idempotency_key_digest: Digest,
        proposal: &FreshserviceIncidentResultProposal,
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
            ticket_mutation: false,
            raw_notes: false,
            outcome_adopted: false,
            work_product_adopted: false,
            recording_digest: Digest::from_text("unsealed-freshservice-recording"),
        };
        result.recording_digest = result.calculate_digest();
        result
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "freshservice-incident-result-recording/v1",
            &[
                (
                    "idempotency",
                    self.idempotency_key_digest.as_str().to_owned(),
                ),
                ("proposal", self.proposal_digest.as_str().to_owned()),
                ("state", format!("{:?}", self.state)),
                ("provenance", self.provenance.as_str().to_owned()),
                ("replayed", self.replayed.to_string()),
                ("connected", self.connected.to_string()),
                ("native", self.native.to_string()),
                ("first_party", self.first_party.to_string()),
                ("provider_receipt", self.provider_receipt.to_string()),
                ("ticket_mutation", self.ticket_mutation.to_string()),
                ("raw_notes", self.raw_notes.to_string()),
                ("outcome_adopted", self.outcome_adopted.to_string()),
                (
                    "work_product_adopted",
                    self.work_product_adopted.to_string(),
                ),
            ],
        )
    }

    pub fn validate_integrity(&self) -> Result<()> {
        self.idempotency_key_digest.validate()?;
        self.proposal_digest.validate()?;
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.ticket_mutation
            || self.raw_notes
            || self.outcome_adopted
            || self.work_product_adopted
            || self.recording_digest != self.calculate_digest()
        {
            return Err(FreshserviceIncidentResultError::TamperedEvidence);
        }
        Ok(())
    }
}

/// Consumer bound to one exact Project/Mission/Work Product and provider registration.
pub struct MissionFreshserviceIncidentConsumer {
    scope: FreshserviceIncidentResultScope,
    registration: FreshserviceIncidentResultRegistration,
    records: BTreeMap<Digest, RecordedFreshserviceIncidentResult>,
}

impl fmt::Debug for MissionFreshserviceIncidentConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionFreshserviceIncidentConsumer")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest(),
            )
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionFreshserviceIncidentConsumer {
    pub fn new(
        scope: FreshserviceIncidentResultScope,
        registration: FreshserviceIncidentResultRegistration,
    ) -> Result<Self> {
        registration.validate()?;
        if !registration.is_active() {
            return Err(FreshserviceIncidentResultError::RegistrationInactive);
        }
        if registration.scope_digest() != &scope.digest()
            || registration.project_revision() != scope.project().revision()
            || registration.mission_revision() != scope.mission().revision()
            || registration.work_product_revision() != scope.work_product().revision()
        {
            return Err(FreshserviceIncidentResultError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    pub fn registration(&self) -> &FreshserviceIncidentResultRegistration {
        &self.registration
    }

    pub fn scope(&self) -> &FreshserviceIncidentResultScope {
        &self.scope
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn has_recorded(&self, idempotency_key: impl AsRef<str>) -> bool {
        self.records
            .contains_key(&self.idempotency_digest(idempotency_key.as_ref()))
    }

    pub fn consume(
        &self,
        proposal: &FreshserviceIncidentResultProposal,
    ) -> Result<MissionFreshserviceIncidentResult> {
        proposal.validate_integrity()?;
        if !self.registration.is_active() {
            return Err(FreshserviceIncidentResultError::RegistrationInactive);
        }
        if proposal.service_id != SERVICE_ID
            || proposal.consumer_id != CONSUMER_ID
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
            || proposal.project.digest != self.scope.project().digest()
            || proposal.project.revision != self.scope.project().revision()
            || proposal.mission.digest != self.scope.mission().digest()
            || proposal.mission.revision != self.scope.mission().revision()
            || proposal.work_product.digest != self.scope.work_product().digest()
            || proposal.work_product.revision != self.scope.work_product().revision()
            || proposal.evidence.scope_digest != self.scope.digest()
            || proposal.evidence.project_digest != self.scope.project().digest()
            || proposal.evidence.mission_digest != self.scope.mission().digest()
            || proposal.evidence.work_product_digest != self.scope.work_product().digest()
        {
            return Err(FreshserviceIncidentResultError::ScopeMismatch);
        }
        Ok(MissionFreshserviceIncidentResult {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.scope_digest.clone(),
            project: proposal.project.clone(),
            mission: proposal.mission.clone(),
            work_product: proposal.work_product.clone(),
            state: proposal.state,
            disposition: proposal.state.into(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            provenance: proposal.provenance,
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            ticket_mutation: false,
            raw_notes: false,
            outcome_adopted: false,
            work_product_adopted: false,
        })
    }

    pub fn record(
        &mut self,
        proposal: &FreshserviceIncidentResultProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<RecordedFreshserviceIncidentResult> {
        let _ = self.consume(proposal)?;
        let key = idempotency_key.as_ref();
        if key.is_empty() || key.len() > MAX_IDENTIFIER_BYTES {
            return Err(FreshserviceIncidentResultError::InvalidRequest);
        }
        let key_digest = self.idempotency_digest(key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(FreshserviceIncidentResultError::RecordingConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            replay.recording_digest = replay.calculate_digest();
            return Ok(replay);
        }
        let result = RecordedFreshserviceIncidentResult::new(key_digest.clone(), proposal, false);
        self.records.insert(key_digest, result.clone());
        Ok(result)
    }

    pub fn revoke(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.revoke()
    }

    pub fn restore(&mut self) -> Result<RegistrationTransitionEvidence> {
        self.registration.restore()?;
        self.registration.activate()
    }

    fn idempotency_digest(&self, key: &str) -> Digest {
        Digest::from_parts(
            "freshservice-idempotency-key/v1",
            &[
                ("key", key.to_owned()),
                ("scope", self.scope.digest().as_str().to_owned()),
                (
                    "registration",
                    self.registration.registration_digest().as_str().to_owned(),
                ),
            ],
        )
    }
}

// Keep the error surface intentionally explicit in generated documentation.
#[allow(dead_code)]
fn _failure_is_redacted(failure: &ObservationFailure) -> bool {
    !matches!(failure, ObservationFailure::Tampered)
}
