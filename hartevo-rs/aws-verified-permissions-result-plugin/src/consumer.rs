use std::fmt;

use serde::Serialize;
use thiserror::Error;

use crate::{
    model::{
        AdoptionAvailability, AuthorizationDecision, AwsVerifiedPermissionsRegistration,
        AwsVerifiedPermissionsScope, ConsentState, ContextReference, EffectGate, EffectState,
        EvidenceState, KernelAuthorizationFence, ModelError, RegistrationState, ReplaySet,
        Revision, VerificationState,
    },
    provider::{AuthorizationProposal, ProviderError},
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConsumerError {
    #[error("Mission AWS Verified Permissions consumer is revoked")]
    Revoked,
    #[error("consumer registration does not match the proposal")]
    RegistrationMismatch,
    #[error("proposal scope does not match the Mission/Work Product scope")]
    ScopeMismatch,
    #[error("kernel Consent fence does not match the registered scope")]
    ConsentMismatch,
    #[error("kernel Effect fence is denied, unknown, or revoked for an ALLOW")]
    EffectFenceMismatch,
    #[error("proposal or record was already observed and replay was rejected")]
    ReplayRejected,
    #[error("proposal or record evidence was tampered")]
    Tampered,
    #[error("verification context does not match the registered context")]
    ContextMismatch,
    #[error("an ALLOW cannot be recorded from partial or lost evidence")]
    UnsafeAllowEvidence,
    #[error("proposal or record is invalid")]
    InvalidEvidence,
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsumerRegistration {
    pub registration_digest: crate::Digest,
    pub scope_digest: crate::Digest,
    pub permission_digest: crate::Digest,
    pub policy_digest: crate::Digest,
    pub context_digest: crate::Digest,
    pub registration_revision: Revision,
    pub state: RegistrationState,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct AuthorizationAuthority;

impl AuthorizationAuthority {
    pub const fn connected(self) -> bool {
        false
    }

    pub const fn native(self) -> bool {
        false
    }

    pub const fn truth(self) -> bool {
        false
    }

    pub const fn adopted(self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorizationRecord {
    pub registration_digest: crate::Digest,
    pub proposal_digest: crate::Digest,
    pub record_revision: Revision,
    pub decision: AuthorizationDecision,
    pub evidence_state: EvidenceState,
    pub determining_policy_digest: Option<crate::Digest>,
    pub principal_digest: crate::Digest,
    pub resource_digest: crate::Digest,
    pub context_digest: crate::Digest,
    pub permission_digest: crate::Digest,
    pub scope_digest: crate::Digest,
    pub policy_digest: crate::Digest,
    pub evidence_digest: crate::Digest,
    pub consent_digest: crate::Digest,
    pub consent_revision: Revision,
    pub effect_digest: crate::Digest,
    pub effect_revision: Revision,
    pub effect_state: EffectState,
    pub effect_gate: EffectGate,
    pub record_digest: crate::Digest,
}

impl AuthorizationRecord {
    pub fn computed_digest(&self) -> crate::Digest {
        crate::Digest::from_fields(
            "aws-verified-permissions-authorization-record/v1",
            &[
                self.registration_digest.as_str().to_owned(),
                self.proposal_digest.as_str().to_owned(),
                self.record_revision.get().to_string(),
                format!("{:?}", self.decision),
                format!("{:?}", self.evidence_state),
                self.determining_policy_digest
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), |digest| digest.as_str().to_owned()),
                self.principal_digest.as_str().to_owned(),
                self.resource_digest.as_str().to_owned(),
                self.context_digest.as_str().to_owned(),
                self.permission_digest.as_str().to_owned(),
                self.scope_digest.as_str().to_owned(),
                self.policy_digest.as_str().to_owned(),
                self.evidence_digest.as_str().to_owned(),
                self.consent_digest.as_str().to_owned(),
                self.consent_revision.get().to_string(),
                self.effect_digest.as_str().to_owned(),
                self.effect_revision.get().to_string(),
                format!("{:?}", self.effect_state),
                format!("{:?}", self.effect_gate),
            ],
        )
    }

    pub fn validate(&self) -> Result<(), ConsumerError> {
        if self.record_digest == self.computed_digest() {
            Ok(())
        } else {
            Err(ConsumerError::Tampered)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorizationVerification {
    pub registration_digest: crate::Digest,
    pub record_digest: crate::Digest,
    pub decision: AuthorizationDecision,
    pub evidence_state: EvidenceState,
    pub verification_state: VerificationState,
    pub permission_digest: crate::Digest,
    pub scope_digest: crate::Digest,
    pub policy_digest: crate::Digest,
    pub context_digest: crate::Digest,
    pub consent_digest: crate::Digest,
    pub effect_digest: crate::Digest,
    pub effect_gate: EffectGate,
    pub execution_permitted: bool,
    pub verification_digest: crate::Digest,
}

impl AuthorizationVerification {
    fn new(record: &AuthorizationRecord, verification_state: VerificationState) -> Self {
        let execution_permitted = false;
        let verification_digest = crate::Digest::from_fields(
            "aws-verified-permissions-authorization-verification/v1",
            &[
                record.registration_digest.as_str().to_owned(),
                record.record_digest.as_str().to_owned(),
                format!("{:?}", record.decision),
                format!("{:?}", record.evidence_state),
                format!("{verification_state:?}"),
                record.permission_digest.as_str().to_owned(),
                record.scope_digest.as_str().to_owned(),
                record.policy_digest.as_str().to_owned(),
                record.context_digest.as_str().to_owned(),
                record.consent_digest.as_str().to_owned(),
                record.effect_digest.as_str().to_owned(),
                format!("{:?}", record.effect_gate),
                execution_permitted.to_string(),
            ],
        );
        Self {
            registration_digest: record.registration_digest.clone(),
            record_digest: record.record_digest.clone(),
            decision: record.decision,
            evidence_state: record.evidence_state,
            verification_state,
            permission_digest: record.permission_digest.clone(),
            scope_digest: record.scope_digest.clone(),
            policy_digest: record.policy_digest.clone(),
            context_digest: record.context_digest.clone(),
            consent_digest: record.consent_digest.clone(),
            effect_digest: record.effect_digest.clone(),
            effect_gate: record.effect_gate,
            execution_permitted,
            verification_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionAwsVerifiedPermissionsResult {
    pub project: crate::ProjectId,
    pub mission: crate::MissionId,
    pub work_product: crate::WorkProductId,
    pub work_product_revision: Revision,
    pub decision: AuthorizationDecision,
    pub evidence_state: EvidenceState,
    pub verification_state: VerificationState,
    pub scope_digest: crate::Digest,
    pub permission_digest: crate::Digest,
    pub policy_digest: crate::Digest,
    pub context_digest: crate::Digest,
    pub verification_digest: crate::Digest,
    pub effect_gate: EffectGate,
    pub adoption: AdoptionAvailability,
    pub authority: AuthorizationAuthority,
}

#[derive(Clone)]
pub struct MissionAwsVerifiedPermissionsConsumer {
    scope: AwsVerifiedPermissionsScope,
    registration: ConsumerRegistration,
    active: bool,
    seen_proposals: ReplaySet,
    seen_records: ReplaySet,
}

impl fmt::Debug for MissionAwsVerifiedPermissionsConsumer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MissionAwsVerifiedPermissionsConsumer")
            .field("scope_digest", self.scope.scope_digest())
            .field("registration", &self.registration)
            .field("active", &self.active)
            .field("seen_proposals", &self.seen_proposals.len())
            .field("seen_records", &self.seen_records.len())
            .finish()
    }
}

impl MissionAwsVerifiedPermissionsConsumer {
    pub fn new(
        scope: AwsVerifiedPermissionsScope,
        registration: &AwsVerifiedPermissionsRegistration,
    ) -> Result<Self, ConsumerError> {
        registration.validate_for_scope(&scope)?;
        registration.ensure_active()?;
        Ok(Self {
            scope,
            registration: ConsumerRegistration {
                registration_digest: registration.registration_digest.clone(),
                scope_digest: registration.scope_digest.clone(),
                permission_digest: registration.permission_digest.clone(),
                policy_digest: registration.policy_digest.clone(),
                context_digest: registration.context_digest.clone(),
                registration_revision: registration.registration_revision,
                state: registration.state,
            },
            active: true,
            seen_proposals: ReplaySet::default(),
            seen_records: ReplaySet::default(),
        })
    }

    pub fn registration(&self) -> &ConsumerRegistration {
        &self.registration
    }

    pub fn scope(&self) -> &AwsVerifiedPermissionsScope {
        &self.scope
    }

    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub fn revoke(&mut self) -> Result<(), ConsumerError> {
        if self.active {
            self.active = false;
            self.registration.state = RegistrationState::Revoked;
            Ok(())
        } else {
            Err(ConsumerError::Revoked)
        }
    }

    pub fn record(
        &mut self,
        proposal: AuthorizationProposal,
        fence: &KernelAuthorizationFence,
    ) -> Result<AuthorizationRecord, ConsumerError> {
        self.ensure_active()?;
        proposal.validate().map_err(|_| ConsumerError::Tampered)?;
        self.validate_proposal_scope(&proposal)?;
        self.validate_kernel_fence(fence)?;
        if proposal.decision == AuthorizationDecision::Allow
            && proposal.evidence_state != EvidenceState::Complete
        {
            return Err(ConsumerError::UnsafeAllowEvidence);
        }
        if !self.seen_proposals.insert(proposal.proposal_digest.clone()) {
            return Err(ConsumerError::ReplayRejected);
        }
        let effect_gate = if proposal.decision == AuthorizationDecision::Allow {
            EffectGate::KernelConsentAndEffectRequired
        } else {
            EffectGate::NotApplicable
        };
        let mut record = AuthorizationRecord {
            registration_digest: self.registration.registration_digest.clone(),
            proposal_digest: proposal.proposal_digest,
            record_revision: Revision::new(1)?,
            decision: proposal.decision,
            evidence_state: proposal.evidence_state,
            determining_policy_digest: proposal
                .determining_policy
                .map(|policy| policy.policy_id_digest),
            principal_digest: proposal.principal_digest,
            resource_digest: proposal.resource_digest,
            context_digest: proposal.context_digest,
            permission_digest: proposal.permission_digest,
            scope_digest: proposal.scope_digest,
            policy_digest: proposal.policy_digest,
            evidence_digest: proposal.evidence_digest,
            consent_digest: fence.consent.consent_digest.clone(),
            consent_revision: fence.consent.revision,
            effect_digest: fence.effect.effect_digest.clone(),
            effect_revision: fence.effect.revision,
            effect_state: fence.effect.state,
            effect_gate,
            record_digest: crate::Digest::from_text([]),
        };
        record.record_digest = record.computed_digest();
        Ok(record)
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn verify(
        &mut self,
        record: AuthorizationRecord,
        fence: &KernelAuthorizationFence,
    ) -> Result<AuthorizationVerification, ConsumerError> {
        let current_context = self.scope.context().clone();
        self.verify_against_context(record, &current_context, fence)
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn verify_against_context(
        &mut self,
        record: AuthorizationRecord,
        current_context: &ContextReference,
        fence: &KernelAuthorizationFence,
    ) -> Result<AuthorizationVerification, ConsumerError> {
        self.ensure_active()?;
        record.validate()?;
        if record.registration_digest != self.registration.registration_digest
            || record.scope_digest != *self.scope.scope_digest()
            || record.permission_digest != *self.scope.permission_digest()
            || record.policy_digest != *self.scope.policy_digest()
            || record.context_digest != *self.scope.context_digest()
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        if current_context.digest() != self.scope.context_digest()
            || record.context_digest != *current_context.digest()
        {
            return Err(ConsumerError::ContextMismatch);
        }
        self.validate_kernel_fence(fence)?;
        if record.consent_digest != fence.consent.consent_digest
            || record.effect_digest != fence.effect.effect_digest
            || record.effect_revision != fence.effect.revision
        {
            return Err(ConsumerError::ConsentMismatch);
        }
        if !self.seen_records.insert(record.record_digest.clone()) {
            return Err(ConsumerError::ReplayRejected);
        }
        let verification_state = match record.evidence_state {
            EvidenceState::Complete => VerificationState::Verified,
            EvidenceState::Partial => VerificationState::Partial,
            EvidenceState::AccessLost => VerificationState::AccessLost,
            EvidenceState::ContextMismatch => return Err(ConsumerError::ContextMismatch),
            EvidenceState::Tampered => return Err(ConsumerError::Tampered),
            EvidenceState::ReplayRejected => return Err(ConsumerError::ReplayRejected),
        };
        Ok(AuthorizationVerification::new(&record, verification_state))
    }

    pub fn consume(
        &self,
        verification: &AuthorizationVerification,
    ) -> Result<MissionAwsVerifiedPermissionsResult, ConsumerError> {
        if !self.active {
            return Err(ConsumerError::Revoked);
        }
        if verification.registration_digest != self.registration.registration_digest
            || verification.scope_digest != *self.scope.scope_digest()
            || verification.permission_digest != *self.scope.permission_digest()
            || verification.policy_digest != *self.scope.policy_digest()
            || verification.context_digest != *self.scope.context_digest()
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        Ok(MissionAwsVerifiedPermissionsResult {
            project: self.scope.project().clone(),
            mission: self.scope.mission().clone(),
            work_product: self.scope.work_product().clone(),
            work_product_revision: self.scope.work_product_revision(),
            decision: verification.decision,
            evidence_state: verification.evidence_state,
            verification_state: verification.verification_state,
            scope_digest: verification.scope_digest.clone(),
            permission_digest: verification.permission_digest.clone(),
            policy_digest: verification.policy_digest.clone(),
            context_digest: verification.context_digest.clone(),
            verification_digest: verification.verification_digest.clone(),
            effect_gate: verification.effect_gate,
            adoption: AdoptionAvailability::NotAdoptedLayer2,
            authority: AuthorizationAuthority,
        })
    }

    pub fn consume_proposal(
        &mut self,
        proposal: AuthorizationProposal,
        fence: &KernelAuthorizationFence,
    ) -> Result<MissionAwsVerifiedPermissionsResult, ConsumerError> {
        let record = self.record(proposal, fence)?;
        let verification = self.verify(record, fence)?;
        self.consume(&verification)
    }

    fn ensure_active(&self) -> Result<(), ConsumerError> {
        if self.active && self.registration.state == RegistrationState::Active {
            Ok(())
        } else {
            Err(ConsumerError::Revoked)
        }
    }

    fn validate_proposal_scope(
        &self,
        proposal: &AuthorizationProposal,
    ) -> Result<(), ConsumerError> {
        if proposal
            .registration_digest
            .as_ref()
            .is_some_and(|digest| digest != &self.registration.registration_digest)
        {
            return Err(ConsumerError::RegistrationMismatch);
        }
        if proposal.scope_digest != *self.scope.scope_digest()
            || proposal.permission_digest != *self.scope.permission_digest()
            || proposal.policy_digest != *self.scope.policy_digest()
            || proposal.context_digest != *self.scope.context_digest()
        {
            return Err(ConsumerError::ScopeMismatch);
        }
        Ok(())
    }

    fn validate_kernel_fence(&self, fence: &KernelAuthorizationFence) -> Result<(), ConsumerError> {
        let consent = self.scope.consent();
        if !consent.is_active()
            || fence.consent.consent_digest != consent.consent_digest
            || fence.consent.revision != consent.revision
            || fence.consent.state != ConsentState::Granted
        {
            return Err(ConsumerError::ConsentMismatch);
        }
        if fence.effect.is_blocked() {
            return Err(ConsumerError::EffectFenceMismatch);
        }
        Ok(())
    }
}

impl From<ProviderError> for ConsumerError {
    fn from(_: ProviderError) -> Self {
        Self::InvalidEvidence
    }
}
