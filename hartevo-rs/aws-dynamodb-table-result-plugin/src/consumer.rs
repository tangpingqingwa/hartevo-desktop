//! Mission-scoped review consumption and idempotent redacted recording.

use std::{collections::BTreeMap, fmt};

use serde::Serialize;

use crate::error::{AwsDynamoDbTableError, Result};
use crate::model::{
    AwsDynamoDbEvidenceState, AwsDynamoDbTableScope, Digest, EvidenceState, MissionProjection,
    ProjectProjection, TransportProvenance, WorkProductProjection, digest_serializable,
    mission_projection, project_projection, work_product_projection,
};
use crate::service::{
    AwsDynamoDbTableEvidence, AwsDynamoDbTableProposal, AwsDynamoDbTableRegistration,
    RegistrationStatus,
};
use crate::{CONSUMER_ID, SERVICE_ID};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalDisposition {
    Completed,
    Partial,
    NotFound,
    AccessLoss,
    Throttled,
    ProviderUnknown,
    TableReplaced,
    SchemaDrift,
    IndexDrift,
    StaleMetadata,
    RegistrationRevoked,
}

impl From<AwsDynamoDbEvidenceState> for ProposalDisposition {
    fn from(state: AwsDynamoDbEvidenceState) -> Self {
        match state {
            EvidenceState::Completed => Self::Completed,
            EvidenceState::Partial => Self::Partial,
            EvidenceState::NotFound => Self::NotFound,
            EvidenceState::AccessLoss => Self::AccessLoss,
            EvidenceState::Throttled => Self::Throttled,
            EvidenceState::ProviderUnknown => Self::ProviderUnknown,
            EvidenceState::TableReplaced => Self::TableReplaced,
            EvidenceState::SchemaDrift => Self::SchemaDrift,
            EvidenceState::IndexDrift => Self::IndexDrift,
            EvidenceState::StaleMetadata => Self::StaleMetadata,
            EvidenceState::RegistrationRevoked => Self::RegistrationRevoked,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsDynamoDbResult {
    pub service_id: &'static str,
    pub consumer_id: &'static str,
    pub mission: MissionProjection,
    pub project: ProjectProjection,
    pub work_product: WorkProductProjection,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub state: AwsDynamoDbEvidenceState,
    pub disposition: ProposalDisposition,
    pub evidence: AwsDynamoDbTableEvidence,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
    pub result_digest: Digest,
}

impl MissionAwsDynamoDbResult {
    pub const fn can_be_adopted(&self) -> bool {
        false
    }

    pub const fn is_review_only(&self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedAwsDynamoDbResult {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub state: AwsDynamoDbEvidenceState,
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

impl RecordedAwsDynamoDbResult {
    fn new(
        idempotency_key_digest: Digest,
        proposal: &AwsDynamoDbTableProposal,
        replayed: bool,
    ) -> Self {
        let mut result = Self {
            idempotency_key_digest,
            proposal_digest: proposal.digest().clone(),
            evidence_digest: proposal.evidence.digest().clone(),
            state: proposal.state,
            disposition: proposal.state.into(),
            provenance: proposal.evidence.provenance.clone(),
            replayed,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            recording_digest: Digest::zero(),
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
            return Err(AwsDynamoDbTableError::TamperedEvidence);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-dynamodb-recording/v1",
            &[
                (
                    "idempotency",
                    self.idempotency_key_digest.as_str().to_owned(),
                ),
                ("proposal", self.proposal_digest.as_str().to_owned()),
                ("evidence", self.evidence_digest.as_str().to_owned()),
                ("state", format!("{:?}", self.state)),
                ("provenance", self.provenance.as_str().to_owned()),
                ("replayed", self.replayed.to_string()),
            ],
        )
    }
}

/// A consumer bound to one exact table scope and one active registration.
pub struct MissionAwsDynamoDbConsumer {
    scope: AwsDynamoDbTableScope,
    registration: AwsDynamoDbTableRegistration,
    records: BTreeMap<Digest, RecordedAwsDynamoDbResult>,
}

impl fmt::Debug for MissionAwsDynamoDbConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAwsDynamoDbConsumer")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest(),
            )
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionAwsDynamoDbConsumer {
    pub fn new(
        scope: AwsDynamoDbTableScope,
        registration: AwsDynamoDbTableRegistration,
    ) -> Result<Self> {
        registration.validate()?;
        if registration.status() != RegistrationStatus::Active
            || registration.scope_digest() != &scope.digest()
        {
            return Err(AwsDynamoDbTableError::RegistrationInactive);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    pub fn scope(&self) -> &AwsDynamoDbTableScope {
        &self.scope
    }

    pub fn registration(&self) -> &AwsDynamoDbTableRegistration {
        &self.registration
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn consume(&self, proposal: &AwsDynamoDbTableProposal) -> Result<MissionAwsDynamoDbResult> {
        if !self.registration.is_active() {
            return Err(AwsDynamoDbTableError::RegistrationInactive);
        }
        proposal.validate_integrity()?;
        if proposal.service_id != SERVICE_ID
            || proposal.consumer_id != CONSUMER_ID
            || proposal.registration_digest != *self.registration.registration_digest()
            || proposal.scope_digest != self.scope.digest()
            || proposal.evidence.registration_digest != *self.registration.registration_digest()
            || proposal.evidence.scope_digest != self.scope.digest()
        {
            return Err(AwsDynamoDbTableError::ScopeMismatch);
        }
        let mission = mission_projection(&self.scope);
        let project = project_projection(&self.scope);
        let work_product = work_product_projection(&self.scope);
        let result_digest = digest_serializable(&(
            SERVICE_ID,
            CONSUMER_ID,
            &mission,
            &project,
            &work_product,
            &proposal.proposal_digest,
            &proposal.evidence.evidence_digest,
            proposal.state,
            false,
            false,
        ))?;
        Ok(MissionAwsDynamoDbResult {
            service_id: SERVICE_ID,
            consumer_id: CONSUMER_ID,
            mission,
            project,
            work_product,
            scope_digest: self.scope.digest(),
            registration_digest: self.registration.registration_digest().clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
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
            result_digest,
        })
    }

    pub fn verify_evidence(&self, evidence: &AwsDynamoDbTableEvidence) -> Result<()> {
        if !self.registration.is_active()
            || evidence.scope_digest != self.scope.digest()
            || evidence.registration_digest != *self.registration.registration_digest()
        {
            return Err(AwsDynamoDbTableError::ScopeMismatch);
        }
        evidence.validate_integrity()
    }

    pub fn record(
        &mut self,
        proposal: &AwsDynamoDbTableProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<RecordedAwsDynamoDbResult> {
        let _ = self.consume(proposal)?;
        let key = idempotency_key.as_ref();
        if key.is_empty() || key.len() > crate::MAX_IDENTIFIER_BYTES {
            return Err(AwsDynamoDbTableError::Model(
                crate::model::ModelError::Invalid {
                    field: "DynamoDB recording idempotency key",
                },
            ));
        }
        let key_digest = Digest::from_text(key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(AwsDynamoDbTableError::RecordingConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            replay.recording_digest = replay.calculate_digest();
            replay.validate_integrity()?;
            return Ok(replay);
        }
        let result = RecordedAwsDynamoDbResult::new(key_digest.clone(), proposal, false);
        self.records.insert(key_digest, result.clone());
        Ok(result)
    }
}
