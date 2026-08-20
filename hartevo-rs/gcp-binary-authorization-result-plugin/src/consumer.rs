use std::{collections::BTreeSet, fmt};

use thiserror::Error;

use crate::{
    Digest, GcpBinaryAuthorizationRegistration, GcpBinaryAuthorizationScope,
    GcpBinaryAuthorizationVerification, Layer1EvidenceAuthority, MissionId, ProjectId,
    RegistrationState, Revision, ValidationDecision, ValidationEvidence, WorkProductId,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ConsumerError {
    #[error("Mission GCP Binary Authorization consumer is revoked")]
    Revoked,
    #[error("consumer registration does not match the scoped registration")]
    RegistrationMismatch,
    #[error("evidence scope does not match the Mission/Project/Work Product scope")]
    ScopeMismatch,
    #[error("evidence permission or consent fence is stale")]
    FenceMismatch,
    #[error("evidence digest is invalid or tampered")]
    TamperedEvidence,
    #[error("evidence has already been consumed")]
    Replay,
    #[error("evidence is not a Layer-1 Binary Authorization observation")]
    InvalidEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumerRegistration {
    pub registration_digest: Digest,
    pub scope_digest: Digest,
    pub revision: Revision,
    pub state: RegistrationState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionGcpBinaryAuthorizationState {
    PendingDecision,
    Layer2AdoptionRequired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionGcpBinaryAuthorizationResult {
    pub project_id: ProjectId,
    pub mission_id: MissionId,
    pub work_product_id: WorkProductId,
    pub work_product_revision: Revision,
    pub image_digest: crate::ImageDigest,
    pub decision: ValidationDecision,
    pub state: MissionGcpBinaryAuthorizationState,
    pub evidence: ValidationEvidence,
    pub evidence_digest: Digest,
    pub authority: Layer1EvidenceAuthority,
    pub adopted_outcome: bool,
    pub durable_adoption: bool,
}

pub struct MissionGcpBinaryAuthorizationConsumer {
    scope: GcpBinaryAuthorizationScope,
    registration: ConsumerRegistration,
    active: bool,
    consumed_evidence: BTreeSet<Digest>,
}

impl fmt::Debug for MissionGcpBinaryAuthorizationConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionGcpBinaryAuthorizationConsumer")
            .field("scope_digest", self.scope.scope_digest())
            .field("registration", &self.registration)
            .field("active", &self.active)
            .field("consumed_evidence_count", &self.consumed_evidence.len())
            .finish()
    }
}

impl MissionGcpBinaryAuthorizationConsumer {
    pub fn new(
        scope: GcpBinaryAuthorizationScope,
        registration: &GcpBinaryAuthorizationRegistration,
    ) -> Result<Self, ConsumerError> {
        if !registration.is_active()
            || registration.scope_digest != *scope.scope_digest()
            || registration.permission_digest != *scope.permission_digest()
            || registration.policy_digest != *scope.policy_digest()
            || registration.attestor_digest != *scope.attestor_digest()
            || registration.image_digest != scope.image_binding_digest()
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        Ok(Self {
            scope,
            registration: ConsumerRegistration {
                registration_digest: registration.registration_digest.clone(),
                scope_digest: registration.scope_digest.clone(),
                revision: registration.revision,
                state: registration.state,
            },
            active: true,
            consumed_evidence: BTreeSet::new(),
        })
    }

    pub fn scope(&self) -> &GcpBinaryAuthorizationScope {
        &self.scope
    }

    pub fn registration(&self) -> &ConsumerRegistration {
        &self.registration
    }

    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub fn revoke(&mut self) -> Result<(), ConsumerError> {
        if !self.active {
            Err(ConsumerError::Revoked)
        } else {
            self.active = false;
            self.registration.state = RegistrationState::Revoked;
            Ok(())
        }
    }

    pub fn consume(
        &mut self,
        verification: GcpBinaryAuthorizationVerification,
    ) -> Result<MissionGcpBinaryAuthorizationResult, ConsumerError> {
        if !self.active {
            return Err(ConsumerError::Revoked);
        }
        self.validate_evidence(&verification.evidence)?;
        if !verification.structurally_valid {
            return Err(ConsumerError::InvalidEvidence);
        }
        let evidence_digest = verification.evidence.evidence_digest().clone();
        if !self.consumed_evidence.insert(evidence_digest.clone()) {
            return Err(ConsumerError::Replay);
        }
        let state = match verification.evidence.decision {
            ValidationDecision::Allow | ValidationDecision::Deny => {
                MissionGcpBinaryAuthorizationState::PendingDecision
            }
            ValidationDecision::Error | ValidationDecision::Unknown => {
                MissionGcpBinaryAuthorizationState::Layer2AdoptionRequired
            }
        };
        Ok(MissionGcpBinaryAuthorizationResult {
            project_id: self.scope.project_id().clone(),
            mission_id: self.scope.mission_id().clone(),
            work_product_id: self.scope.work_product_id().clone(),
            work_product_revision: self.scope.work_product_revision(),
            image_digest: verification.evidence.image_digest.clone(),
            decision: verification.evidence.decision,
            state,
            evidence: verification.evidence,
            evidence_digest,
            authority: Layer1EvidenceAuthority,
            adopted_outcome: false,
            durable_adoption: false,
        })
    }

    pub fn consume_evidence(
        &mut self,
        evidence: ValidationEvidence,
    ) -> Result<MissionGcpBinaryAuthorizationResult, ConsumerError> {
        self.consume(GcpBinaryAuthorizationVerification {
            evidence,
            structurally_valid: true,
        })
    }

    fn validate_evidence(&self, evidence: &ValidationEvidence) -> Result<(), ConsumerError> {
        if evidence.scope_digest != *self.scope.scope_digest()
            || evidence.permission_digest != *self.scope.permission_digest()
            || evidence.consent_digest != *self.scope.consent_digest()
            || evidence.policy_digest != *self.scope.policy_digest()
            || evidence.attestor_digest != *self.scope.attestor_digest()
            || evidence.image_digest != *self.scope.image_digest()
            || evidence.digests.scope_digest != evidence.scope_digest
            || evidence.digests.permission_digest != evidence.permission_digest
            || evidence.digests.policy_digest != evidence.policy_digest
            || evidence.digests.attestor_digest != evidence.attestor_digest
            || evidence.digests.image_digest != evidence.image_digest.digest()
            || evidence.digests.evidence_digest != evidence.digests.recompute()
            || evidence.authority != Layer1EvidenceAuthority
            || evidence.adopted_outcome
            || evidence.durable_receipt
        {
            return Err(ConsumerError::FenceMismatch);
        }
        if self.registration.state != RegistrationState::Active
            || self.registration.scope_digest != *self.scope.scope_digest()
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        Ok(())
    }
}

pub type MissionGcpBinaryAuthorizationResultConsumer = MissionGcpBinaryAuthorizationConsumer;
