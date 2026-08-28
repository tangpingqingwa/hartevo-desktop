//! Mission-scoped proposal consumption and idempotent recording.

use std::{collections::BTreeMap, fmt};

use serde::Serialize;

use crate::{
    CONSUMER_ID, SERVICE_ID,
    model::{
        AwsRdsHealthScope, AwsRdsHealthState, DeploymentProjection, Digest, MissionProjection,
        ProjectProjection, TransportProvenance, WorkProductProjection,
    },
    service::{AwsRdsHealthProposal, AwsRdsRegistration, AwsRdsServiceError, RegistrationState},
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionAwsRdsDecision {
    Proceed,
    Review,
    Blocked,
    Unknown,
}

impl From<AwsRdsHealthState> for MissionAwsRdsDecision {
    fn from(state: AwsRdsHealthState) -> Self {
        match state {
            AwsRdsHealthState::Healthy => Self::Proceed,
            AwsRdsHealthState::Degraded => Self::Review,
            AwsRdsHealthState::Unavailable
            | AwsRdsHealthState::NotFound
            | AwsRdsHealthState::Partial
            | AwsRdsHealthState::AccessLoss
            | AwsRdsHealthState::Throttled
            | AwsRdsHealthState::TimedOut
            | AwsRdsHealthState::RegistrationRevoked => Self::Blocked,
            AwsRdsHealthState::ProviderUnknown => Self::Unknown,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsRdsResult {
    pub service_id: String,
    pub consumer_id: String,
    pub deployment: DeploymentProjection,
    pub mission: MissionProjection,
    pub project: ProjectProjection,
    pub work_product: WorkProductProjection,
    pub proposal_digest: Digest,
    pub scope_digest: Digest,
    pub evidence_digest: Digest,
    pub state: AwsRdsHealthState,
    pub decision: MissionAwsRdsDecision,
    pub provenance: TransportProvenance,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

impl MissionAwsRdsResult {
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedAwsRdsResult {
    pub idempotency_key_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub state: AwsRdsHealthState,
    pub decision: MissionAwsRdsDecision,
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

impl RecordedAwsRdsResult {
    fn new(
        idempotency_key_digest: Digest,
        proposal: &AwsRdsHealthProposal,
        replayed: bool,
    ) -> Self {
        let mut result = Self {
            idempotency_key_digest,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digests.evidence_digest.clone(),
            state: proposal.state,
            decision: proposal.state.into(),
            provenance: proposal.evidence.provenance,
            replayed,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            recording_digest: Digest::zero(),
        };
        result.recording_digest = result.recomputed_digest();
        result
    }

    pub fn recomputed_digest(&self) -> Digest {
        Digest::from_parts(
            "aws-rds-recording/v1",
            &[
                ("idempotency", self.idempotency_key_digest.to_string()),
                ("proposal", self.proposal_digest.to_string()),
                ("evidence", self.evidence_digest.to_string()),
                ("state", format!("{:?}", self.state)),
                ("decision", format!("{:?}", self.decision)),
                ("provenance", self.provenance.as_str().to_owned()),
                ("replayed", self.replayed.to_string()),
            ],
        )
    }

    pub fn validate_integrity(&self) -> Result<(), AwsRdsServiceError> {
        if self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.outcome_adopted
            || self.work_product_adopted
            || self.recording_digest != self.recomputed_digest()
        {
            return Err(AwsRdsServiceError::EvidenceTampered);
        }
        Ok(())
    }
}

pub struct MissionAwsRdsConsumer {
    scope: AwsRdsHealthScope,
    registration: AwsRdsRegistration,
    records: BTreeMap<Digest, RecordedAwsRdsResult>,
}

impl fmt::Debug for MissionAwsRdsConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAwsRdsConsumer")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                &self.registration.registration_digest,
            )
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionAwsRdsConsumer {
    pub fn new(
        scope: AwsRdsHealthScope,
        registration: AwsRdsRegistration,
    ) -> Result<Self, AwsRdsServiceError> {
        scope.validate()?;
        if !registration.is_active() || registration.scope_digest != scope.digest() {
            return Err(AwsRdsServiceError::RegistrationRevoked);
        }
        if registration.registration_digest != registration.recomputed_digest() {
            return Err(AwsRdsServiceError::RegistrationDrift(
                "registration digest".to_owned(),
            ));
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    pub fn scope(&self) -> &AwsRdsHealthScope {
        &self.scope
    }

    pub fn registration(&self) -> &AwsRdsRegistration {
        &self.registration
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn consume(
        &self,
        proposal: &AwsRdsHealthProposal,
    ) -> Result<MissionAwsRdsResult, AwsRdsServiceError> {
        proposal.validate(&self.scope)?;
        if !self.registration.is_active() {
            return Err(AwsRdsServiceError::RegistrationRevoked);
        }
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.evidence.scope_digest != self.scope.digest()
            || proposal.deployment.id_digest != self.scope.deployment.id.digest()
            || proposal.mission.id_digest != self.scope.mission.id.digest()
            || proposal.project.id_digest != self.scope.project.id.digest()
            || proposal.work_product.id_digest != self.scope.work_product.id.digest()
        {
            return Err(AwsRdsServiceError::ScopeMismatch(
                "Mission Project Work Product or registration".to_owned(),
            ));
        }
        Ok(MissionAwsRdsResult {
            service_id: SERVICE_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            deployment: proposal.deployment.clone(),
            mission: proposal.mission.clone(),
            project: proposal.project.clone(),
            work_product: proposal.work_product.clone(),
            proposal_digest: proposal.proposal_digest.clone(),
            scope_digest: proposal.evidence.scope_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digests.evidence_digest.clone(),
            state: proposal.state,
            decision: proposal.state.into(),
            provenance: proposal.evidence.provenance,
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
        proposal: &AwsRdsHealthProposal,
        idempotency_key: impl AsRef<str>,
    ) -> Result<RecordedAwsRdsResult, AwsRdsServiceError> {
        let _ = self.consume(proposal)?;
        let key = idempotency_key.as_ref();
        if key.is_empty() || key.len() > crate::MAX_IDENTIFIER_BYTES {
            return Err(AwsRdsServiceError::Model(crate::ModelError::Invalid {
                field: "idempotency key",
            }));
        }
        let key_digest = Digest::from_text(key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(AwsRdsServiceError::RecordingConflict);
            }
            let mut replay = existing.clone();
            replay.replayed = true;
            replay.recording_digest = replay.recomputed_digest();
            return Ok(replay);
        }
        if self.registration.state != RegistrationState::Active {
            return Err(AwsRdsServiceError::RegistrationRevoked);
        }
        let result = RecordedAwsRdsResult::new(key_digest.clone(), proposal, false);
        self.records.insert(key_digest, result.clone());
        Ok(result)
    }

    pub fn verify_record(&self, record: &RecordedAwsRdsResult) -> Result<(), AwsRdsServiceError> {
        record.validate_integrity()?;
        if record.proposal_digest.is_zero() || record.evidence_digest.is_zero() {
            return Err(AwsRdsServiceError::RecordTampered);
        }
        Ok(())
    }
}
