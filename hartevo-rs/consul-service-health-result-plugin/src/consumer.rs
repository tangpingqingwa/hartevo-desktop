use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    AuthorityBoundary, CONSUL_CONSUMER_ID,
    model::{Digest, EvidenceStatus, Mission, Project, Revision, Scope, WorkProduct},
    service::{
        ConsulLocalRecord, ConsulRegistration, ConsulServiceHealthReadResult, ConsulVerification,
        RegistrationState, ServiceError,
    },
};

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ConsumerError {
    #[error("Mission Consul service-health consumer is revoked")]
    Revoked,
    #[error("consumer registration does not match the proposal")]
    RegistrationMismatch,
    #[error("proposal scope does not match Project/Mission/Work Product scope")]
    ScopeMismatch,
    #[error("Mission revision is stale")]
    StaleMission,
    #[error("proposal or evidence was tampered")]
    Tampered,
    #[error("proposal replay was rejected")]
    Replay,
    #[error("evidence state is not consumable")]
    InvalidEvidence,
    #[error(transparent)]
    Model(#[from] crate::ModelError),
    #[error(transparent)]
    Service(#[from] ServiceError),
    #[error(transparent)]
    Registration(#[from] crate::ConsulRegistrationError),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionConsulServiceHealthResult {
    pub consumer_id: String,
    pub project: Project,
    pub mission: Mission,
    pub work_product: WorkProduct,
    pub mission_revision: Revision,
    pub status: EvidenceStatus,
    pub registration_digest: Digest,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub record: Option<ConsulLocalRecord>,
    pub accepted: bool,
    pub review_only: bool,
    pub adopted: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub authority: AuthorityBoundary,
    pub result_digest: Digest,
}

impl MissionConsulServiceHealthResult {
    fn new(
        scope: &Scope,
        registration: &ConsulRegistration,
        result: &ConsulServiceHealthReadResult,
        record: Option<ConsulLocalRecord>,
    ) -> Self {
        let status = record
            .as_ref()
            .map_or(result.evidence.status, |value| value.status);
        let review_only = !status.is_review_complete();
        let mut output = Self {
            consumer_id: CONSUL_CONSUMER_ID.to_owned(),
            project: scope.project.clone(),
            mission: scope.mission.clone(),
            work_product: scope.work_product.clone(),
            mission_revision: scope.mission.revision,
            status,
            registration_digest: registration.registration_digest.clone(),
            proposal_digest: result.proposal.proposal_digest.clone(),
            evidence_digest: result.evidence.evidence_digest.clone(),
            record,
            accepted: true,
            review_only,
            adopted: false,
            connected: false,
            native: false,
            first_party: false,
            authority: AuthorityBoundary::layer_one(),
            result_digest: Digest::from_text("uninitialized-consumer-result"),
        };
        output.result_digest = output.computed_digest();
        output
    }

    fn replay(
        scope: &Scope,
        registration: &ConsulRegistration,
        result: &ConsulServiceHealthReadResult,
        record: &ConsulLocalRecord,
    ) -> Self {
        Self::new(scope, registration, result, Some(record.replayed_copy()))
    }

    pub fn computed_digest(&self) -> Digest {
        Digest::from_parts(
            "mission-consul-service-health-result/v1",
            &[
                self.consumer_id.as_str(),
                self.project.digest().as_str(),
                self.mission.digest().as_str(),
                self.work_product.digest().as_str(),
                &self.mission_revision.get().to_string(),
                self.status.as_str(),
                self.registration_digest.as_str(),
                self.proposal_digest.as_str(),
                self.evidence_digest.as_str(),
                self.record
                    .as_ref()
                    .map_or("none", |record| record.record_digest.as_str()),
                &self.accepted.to_string(),
                &self.review_only.to_string(),
                &self.adopted.to_string(),
            ],
        )
    }

    pub fn validate(&self) -> Result<(), ConsumerError> {
        if self.consumer_id != CONSUL_CONSUMER_ID
            || !self.accepted
            || self.adopted
            || self.connected
            || self.native
            || self.first_party
            || self.authority != AuthorityBoundary::layer_one()
            || self.result_digest != self.computed_digest()
        {
            Err(ConsumerError::Tampered)
        } else {
            Ok(())
        }
    }
}

pub struct MissionConsulServiceHealthConsumer {
    scope: Scope,
    registration: ConsulRegistration,
    active: bool,
    seen_proposals: BTreeSet<Digest>,
    records: BTreeMap<Digest, ConsulLocalRecord>,
    next_record_revision: Revision,
}

impl fmt::Debug for MissionConsulServiceHealthConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionConsulServiceHealthConsumer")
            .field("scope_digest", self.scope.scope_digest())
            .field("registration", &self.registration)
            .field("active", &self.active)
            .field("seen_proposals", &self.seen_proposals.len())
            .field("records", &self.records.len())
            .field("next_record_revision", &self.next_record_revision)
            .finish()
    }
}

impl MissionConsulServiceHealthConsumer {
    pub fn new(scope: Scope, registration: &ConsulRegistration) -> Result<Self, ConsumerError> {
        scope.validate()?;
        registration.validate_integrity()?;
        if registration.scope_digest != *scope.scope_digest()
            || registration.permission_digest != scope.permission_digest()
            || registration.consent_digest != scope.consent_digest()
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        if registration.state == RegistrationState::Revoked {
            return Err(ConsumerError::Revoked);
        }
        Ok(Self {
            scope,
            registration: registration.clone(),
            active: true,
            seen_proposals: BTreeSet::new(),
            records: BTreeMap::new(),
            next_record_revision: Revision::new(1)?,
        })
    }

    pub fn scope(&self) -> &Scope {
        &self.scope
    }

    pub fn registration(&self) -> &ConsulRegistration {
        &self.registration
    }

    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn consume(
        &mut self,
        result: &ConsulServiceHealthReadResult,
    ) -> Result<MissionConsulServiceHealthResult, ConsumerError> {
        self.consume_at(result, self.scope.mission.revision)
    }

    pub fn consume_at(
        &mut self,
        result: &ConsulServiceHealthReadResult,
        mission_revision: Revision,
    ) -> Result<MissionConsulServiceHealthResult, ConsumerError> {
        self.ensure_active()?;
        if mission_revision != self.scope.mission.revision {
            return Err(ConsumerError::StaleMission);
        }
        self.validate_result(result)?;
        if !self
            .seen_proposals
            .insert(result.proposal.proposal_digest.clone())
        {
            return Err(ConsumerError::Replay);
        }
        Ok(MissionConsulServiceHealthResult::new(
            &self.scope,
            &self.registration,
            result,
            None,
        ))
    }

    pub fn record(
        &mut self,
        result: &ConsulServiceHealthReadResult,
        idempotency_key: impl AsRef<[u8]>,
    ) -> Result<MissionConsulServiceHealthResult, ConsumerError> {
        self.ensure_active()?;
        self.validate_result(result)?;
        let key = Digest::from_text(idempotency_key);
        if let Some(existing) = self.records.get(&key) {
            if existing.proposal_digest == result.proposal.proposal_digest {
                return Ok(MissionConsulServiceHealthResult::replay(
                    &self.scope,
                    &self.registration,
                    result,
                    existing,
                ));
            }
            return Err(ConsumerError::Replay);
        }
        if !self
            .seen_proposals
            .insert(result.proposal.proposal_digest.clone())
        {
            return Err(ConsumerError::Replay);
        }
        let record = ConsulLocalRecord::from_proposal(&result.proposal, self.next_record_revision);
        self.next_record_revision = self.next_record_revision.next()?;
        self.records.insert(key, record.clone());
        Ok(MissionConsulServiceHealthResult::new(
            &self.scope,
            &self.registration,
            result,
            Some(record),
        ))
    }

    pub fn verify(&self, record: &ConsulLocalRecord) -> ConsulVerification {
        if !self.active {
            return ConsulVerification::from_record(record, crate::VerificationState::Revoked);
        }
        if record.registration_digest != self.registration.registration_digest {
            return ConsulVerification::from_record(record, crate::VerificationState::Tampered);
        }
        if record.replayed {
            ConsulVerification::from_record(record, crate::VerificationState::Replay)
        } else if record.validate().is_err() {
            ConsulVerification::from_record(record, crate::VerificationState::Tampered)
        } else {
            ConsulVerification::from_record(record, crate::VerificationState::Verified)
        }
    }

    pub fn revoke(&mut self) -> Result<(), ConsumerError> {
        self.ensure_active()?;
        self.active = false;
        self.registration.revoke()?;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<(), ConsumerError> {
        if self.active {
            return Err(ConsumerError::Replay);
        }
        self.registration.restore()?;
        self.active = true;
        Ok(())
    }

    fn ensure_active(&self) -> Result<(), ConsumerError> {
        if self.active && self.registration.is_active() {
            Ok(())
        } else {
            Err(ConsumerError::Revoked)
        }
    }

    fn validate_result(&self, result: &ConsulServiceHealthReadResult) -> Result<(), ConsumerError> {
        result.evidence.validate()?;
        result.proposal.validate()?;
        if result.proposal.registration_digest != self.registration.registration_digest
            || result.proposal.scope_digest != *self.scope.scope_digest()
            || result.proposal.permission_digest != self.scope.permission_digest()
            || result.proposal.consent_digest != self.scope.consent_digest()
            || self.registration.evidence_digest.as_ref() != Some(&result.evidence.evidence_digest)
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        if matches!(
            result.evidence.status,
            EvidenceStatus::Tampered | EvidenceStatus::Replay | EvidenceStatus::Revoked
        ) {
            return Err(ConsumerError::InvalidEvidence);
        }
        Ok(())
    }
}
