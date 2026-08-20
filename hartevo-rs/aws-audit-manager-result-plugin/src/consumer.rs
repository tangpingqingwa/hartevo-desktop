//! Mission-scoped non-authoritative consumption and idempotent recording.

use std::{collections::BTreeMap, fmt};

use serde::Serialize;
use thiserror::Error;

use crate::AWS_AUDIT_MANAGER_CONSUMER_ID;
use crate::error::AwsAuditManagerError;
use crate::model::{
    AuditManagerEvidenceState, AwsAuditManagerScope, Digest, EvidencePeriod, ProviderProvenance,
};
use crate::service::{
    AwsAuditManagerProposal, AwsAuditManagerRegistration, RecordedAwsAuditManagerResult,
    RegistrationState,
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("Mission AWS Audit Manager consumer registration is revoked")]
    RegistrationRevoked,
    #[error("Mission AWS Audit Manager consumer registration is reversed")]
    RegistrationReversed,
    #[error("Mission AWS Audit Manager consumer registration or scope does not match")]
    ScopeMismatch,
    #[error("Mission AWS Audit Manager consumer proposal is stale or tampered")]
    ProposalTampered,
    #[error("Mission AWS Audit Manager consumer recording key conflicts with existing evidence")]
    RecordingConflict,
    #[error("Mission AWS Audit Manager consumer could not validate service evidence: {0}")]
    Service(#[from] AwsAuditManagerError),
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionAwsAuditManagerDecisionState {
    ReviewRequired,
    Complete,
    InProgress,
    Partial,
    Expired,
    AccessLoss,
    NotFound,
    Throttled,
    ProviderUnknown,
    AssessmentDrift,
    FrameworkDrift,
    ControlSetDrift,
    ReportDrift,
    RegistrationRevoked,
}

impl From<AuditManagerEvidenceState> for MissionAwsAuditManagerDecisionState {
    fn from(state: AuditManagerEvidenceState) -> Self {
        match state {
            AuditManagerEvidenceState::Complete => Self::Complete,
            AuditManagerEvidenceState::InProgress => Self::InProgress,
            AuditManagerEvidenceState::Partial => Self::Partial,
            AuditManagerEvidenceState::Expired => Self::Expired,
            AuditManagerEvidenceState::AccessLoss => Self::AccessLoss,
            AuditManagerEvidenceState::NotFound => Self::NotFound,
            AuditManagerEvidenceState::Throttled => Self::Throttled,
            AuditManagerEvidenceState::ProviderUnknown
            | AuditManagerEvidenceState::UnregisteredAccount => Self::ProviderUnknown,
            AuditManagerEvidenceState::AssessmentDrift => Self::AssessmentDrift,
            AuditManagerEvidenceState::FrameworkDrift => Self::FrameworkDrift,
            AuditManagerEvidenceState::ControlSetDrift => Self::ControlSetDrift,
            AuditManagerEvidenceState::ReportDrift => Self::ReportDrift,
            AuditManagerEvidenceState::RegistrationRevoked => Self::RegistrationRevoked,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MissionAwsAuditManagerResult {
    pub service_id: &'static str,
    pub consumer_id: &'static str,
    pub mission: crate::model::MissionIdentity,
    pub project: crate::model::ProjectIdentity,
    pub work_product: crate::model::WorkProductIdentity,
    pub scope_digest: Digest,
    pub registration_digest: Digest,
    pub request_digest: Digest,
    pub evidence_digest: Digest,
    pub state: AuditManagerEvidenceState,
    pub decision_state: MissionAwsAuditManagerDecisionState,
    pub evidence_period: Option<EvidencePeriod>,
    pub provenance: ProviderProvenance,
    pub review_only: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub certification_claim: bool,
    pub legal_advice: bool,
    pub outcome_adopted: bool,
    pub work_product_adopted: bool,
}

impl MissionAwsAuditManagerResult {
    pub const fn can_be_adopted(&self) -> bool {
        false
    }
}

pub struct MissionAwsAuditManagerConsumer {
    scope: AwsAuditManagerScope,
    registration: AwsAuditManagerRegistration,
    records: BTreeMap<Digest, RecordedAwsAuditManagerResult>,
}

impl fmt::Debug for MissionAwsAuditManagerConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAwsAuditManagerConsumer")
            .field("scope_digest", &self.scope.digest())
            .field(
                "registration_digest",
                self.registration.registration_digest(),
            )
            .field("record_count", &self.records.len())
            .finish()
    }
}

impl MissionAwsAuditManagerConsumer {
    pub fn new(
        scope: AwsAuditManagerScope,
        registration: AwsAuditManagerRegistration,
    ) -> std::result::Result<Self, ConsumerError> {
        if registration.status() != RegistrationState::Active {
            return Err(match registration.status() {
                RegistrationState::Revoked => ConsumerError::RegistrationRevoked,
                RegistrationState::Reversed => ConsumerError::RegistrationReversed,
                RegistrationState::Active => ConsumerError::ScopeMismatch,
            });
        }
        if registration.scope().digest() != scope.digest()
            || registration.registration_digest() != &registration.recomputed_digest()
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        Ok(Self {
            scope,
            registration,
            records: BTreeMap::new(),
        })
    }

    pub fn scope(&self) -> &AwsAuditManagerScope {
        &self.scope
    }

    pub fn registration(&self) -> &AwsAuditManagerRegistration {
        &self.registration
    }

    pub fn registration_digest(&self) -> &Digest {
        self.registration.registration_digest()
    }

    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    pub fn consume(
        &self,
        proposal: &AwsAuditManagerProposal,
    ) -> std::result::Result<MissionAwsAuditManagerResult, ConsumerError> {
        proposal
            .validate_integrity()
            .map_err(|_| ConsumerError::ProposalTampered)?;
        if self.registration.status() != RegistrationState::Active {
            return Err(match self.registration.status() {
                RegistrationState::Revoked => ConsumerError::RegistrationRevoked,
                RegistrationState::Reversed => ConsumerError::RegistrationReversed,
                RegistrationState::Active => ConsumerError::ScopeMismatch,
            });
        }
        if proposal.registration_digest != *self.registration.registration_digest()
            || proposal.evidence_binding_digest != *self.registration.evidence_binding_digest()
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        Ok(MissionAwsAuditManagerResult {
            service_id: crate::AWS_AUDIT_MANAGER_SERVICE_ID,
            consumer_id: AWS_AUDIT_MANAGER_CONSUMER_ID,
            mission: self.scope.mission().clone(),
            project: self.scope.project().clone(),
            work_product: self.scope.work_product().clone(),
            scope_digest: self.scope.digest(),
            registration_digest: self.registration.registration_digest().clone(),
            request_digest: proposal.request_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            state: proposal.evidence.state.clone(),
            decision_state: proposal.evidence.state.clone().into(),
            evidence_period: proposal.evidence.evidence_period.clone(),
            provenance: proposal.evidence.provenance,
            review_only: true,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            certification_claim: false,
            legal_advice: false,
            outcome_adopted: false,
            work_product_adopted: false,
        })
    }

    pub fn verify_evidence(
        &self,
        proposal: &AwsAuditManagerProposal,
    ) -> std::result::Result<(), ConsumerError> {
        let _ = self.consume(proposal)?;
        Ok(())
    }

    pub fn record(
        &mut self,
        proposal: &AwsAuditManagerProposal,
        idempotency_key: impl AsRef<str>,
    ) -> std::result::Result<RecordedAwsAuditManagerResult, ConsumerError> {
        let _ = self.consume(proposal)?;
        let key = idempotency_key.as_ref();
        if key.is_empty()
            || key.len() > crate::MAX_IDENTIFIER_BYTES
            || key.chars().any(char::is_control)
        {
            return Err(ConsumerError::Service(AwsAuditManagerError::InvalidRequest));
        }
        let key_digest = Digest::from_text(key);
        if let Some(existing) = self.records.get(&key_digest) {
            if existing.proposal_digest != proposal.proposal_digest {
                return Err(ConsumerError::RecordingConflict);
            }
            let replay = RecordedAwsAuditManagerResult::new(key_digest.clone(), proposal, true);
            self.records.insert(key_digest, replay.clone());
            return Ok(replay);
        }
        let value = RecordedAwsAuditManagerResult::new(key_digest.clone(), proposal, false);
        self.records.insert(key_digest, value.clone());
        Ok(value)
    }
}

pub type MissionAwsAuditManagerConsumerError = ConsumerError;
pub type MissionAwsAuditManagerDecision = MissionAwsAuditManagerDecisionState;
pub type MissionAwsAuditManagerResultReceipt = MissionAwsAuditManagerResult;
