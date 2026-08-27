//! Mission-side proposal consumer for bounded Security Command Center
//! evidence.

use std::fmt;

use thiserror::Error;

use crate::{
    AdoptionAvailability, EvidenceAuthority, EvidenceProjection, FindingsGroupReceipt,
    FindingsGroupVerification, FindingsListReceipt, FindingsListVerification,
    GcpSecurityCenterRegistration, GcpSecurityCenterScope, MissionId, MissionObservation,
    MissionResultState, ProjectScope, Revision, WorkProductId,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ConsumerError {
    #[error("Mission GCP Security Command Center consumer is revoked")]
    Revoked,
    #[error("consumer registration does not match the active provider registration")]
    RegistrationMismatch,
    #[error("evidence scope does not match the Mission Project/Mission/Work Product scope")]
    ScopeMismatch,
    #[error("verification failed or was tampered")]
    VerificationFailed,
    #[error("evidence was not produced by the governed read-only service")]
    InvalidEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionGcpSecurityCenterResult {
    pub project: ProjectScope,
    pub mission_id: MissionId,
    pub work_product_id: WorkProductId,
    pub work_product_revision: Revision,
    pub observation: MissionObservation,
    pub state: MissionResultState,
    pub evidence_digest: crate::Digest,
    pub receipt_digest: crate::Digest,
    pub verification_digest: crate::Digest,
    pub authority: EvidenceAuthority,
    pub adoption: AdoptionAvailability,
}

pub struct MissionGcpSecurityCenterConsumer {
    scope: GcpSecurityCenterScope,
    registration: GcpSecurityCenterRegistration,
    active: bool,
}

impl fmt::Debug for MissionGcpSecurityCenterConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionGcpSecurityCenterConsumer")
            .field("scope_digest", &self.scope.scope_digest())
            .field("registration", &self.registration)
            .field("active", &self.active)
            .finish()
    }
}

impl MissionGcpSecurityCenterConsumer {
    pub fn new(
        scope: GcpSecurityCenterScope,
        registration: &GcpSecurityCenterRegistration,
    ) -> Result<Self, ConsumerError> {
        if !registration.is_active()
            || registration.scope_digest != *scope.scope_digest()
            || registration.permission_digest != *scope.permissions().digest()
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        Ok(Self {
            scope,
            registration: registration.clone(),
            active: true,
        })
    }

    pub fn scope(&self) -> &GcpSecurityCenterScope {
        &self.scope
    }

    pub fn registration(&self) -> &GcpSecurityCenterRegistration {
        &self.registration
    }

    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub fn revoke(&mut self) -> Result<(), ConsumerError> {
        if !self.active {
            return Err(ConsumerError::Revoked);
        }
        self.active = false;
        self.registration.state = crate::RegistrationState::Revoked;
        Ok(())
    }

    pub fn consume_findings_list(
        &self,
        receipt: &FindingsListReceipt,
        verification: &FindingsListVerification,
    ) -> Result<MissionGcpSecurityCenterResult, ConsumerError> {
        self.ensure_active()?;
        receipt
            .validate_integrity()
            .map_err(|_| ConsumerError::VerificationFailed)?;
        verification
            .validate_integrity()
            .map_err(|_| ConsumerError::VerificationFailed)?;
        if verification.evidence_digest != receipt.evidence_digest
            || verification.receipt_digest != receipt.receipt_digest
        {
            return Err(ConsumerError::VerificationFailed);
        }
        let evidence = &receipt.evidence;
        self.validate_evidence_binding(
            evidence.registration_digest.clone(),
            evidence.registration_revision,
            evidence.scope_digest.clone(),
            evidence.permission_digest.clone(),
            evidence.authority,
            evidence.classification,
        )?;
        Ok(MissionGcpSecurityCenterResult {
            project: self.scope.project().clone(),
            mission_id: self.scope.mission().id.clone(),
            work_product_id: self.scope.work_product().id.clone(),
            work_product_revision: self.scope.work_product().revision,
            state: state_for(&evidence.projection),
            observation: MissionObservation::FindingsList(evidence.clone()),
            evidence_digest: evidence.evidence_digest.clone(),
            receipt_digest: receipt.receipt_digest.clone(),
            verification_digest: verification.verification_digest.clone(),
            authority: EvidenceAuthority::layer1(),
            adoption: AdoptionAvailability::NotAdoptedLayer2,
        })
    }

    pub fn consume_findings_group(
        &self,
        receipt: &FindingsGroupReceipt,
        verification: &FindingsGroupVerification,
    ) -> Result<MissionGcpSecurityCenterResult, ConsumerError> {
        self.ensure_active()?;
        receipt
            .validate_integrity()
            .map_err(|_| ConsumerError::VerificationFailed)?;
        verification
            .validate_integrity()
            .map_err(|_| ConsumerError::VerificationFailed)?;
        if verification.evidence_digest != receipt.evidence_digest
            || verification.receipt_digest != receipt.receipt_digest
        {
            return Err(ConsumerError::VerificationFailed);
        }
        let evidence = &receipt.evidence;
        self.validate_evidence_binding(
            evidence.registration_digest.clone(),
            evidence.registration_revision,
            evidence.scope_digest.clone(),
            evidence.permission_digest.clone(),
            evidence.authority,
            evidence.classification,
        )?;
        Ok(MissionGcpSecurityCenterResult {
            project: self.scope.project().clone(),
            mission_id: self.scope.mission().id.clone(),
            work_product_id: self.scope.work_product().id.clone(),
            work_product_revision: self.scope.work_product().revision,
            state: state_for(&evidence.projection),
            observation: MissionObservation::FindingsGroup(evidence.clone()),
            evidence_digest: evidence.evidence_digest.clone(),
            receipt_digest: receipt.receipt_digest.clone(),
            verification_digest: verification.verification_digest.clone(),
            authority: EvidenceAuthority::layer1(),
            adoption: AdoptionAvailability::NotAdoptedLayer2,
        })
    }

    fn ensure_active(&self) -> Result<(), ConsumerError> {
        if self.active {
            Ok(())
        } else {
            Err(ConsumerError::Revoked)
        }
    }

    fn validate_evidence_binding(
        &self,
        registration_digest: crate::Digest,
        registration_revision: u64,
        scope_digest: crate::Digest,
        permission_digest: crate::Digest,
        authority: EvidenceAuthority,
        classification: crate::TransportProvenance,
    ) -> Result<(), ConsumerError> {
        if registration_digest != self.registration.registration_digest
            || registration_revision != self.registration.registration_revision
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        if scope_digest != *self.scope.scope_digest()
            || permission_digest != *self.scope.permissions().digest()
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        if authority != EvidenceAuthority::layer1()
            || classification.is_native()
            || classification.is_connected()
        {
            return Err(ConsumerError::InvalidEvidence);
        }
        Ok(())
    }
}

fn state_for(projection: &EvidenceProjection) -> MissionResultState {
    match projection {
        EvidenceProjection::Complete => MissionResultState::PendingDecision,
        EvidenceProjection::Partial(_) => MissionResultState::Layer2AdoptionRequired,
        EvidenceProjection::AccessLost => MissionResultState::AccessLost,
        EvidenceProjection::ProviderUnknown => MissionResultState::ProviderUnknown,
    }
}
