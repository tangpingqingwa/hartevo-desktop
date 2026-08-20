//! Mission-scoped Boundary session-result service.
//!
//! All provider operations are bounded GET reads. Local proposal/recording
//! and integrity checks are explicit and never claim a durable provider
//! receipt or Hartevo kernel authority.

use std::{collections::BTreeSet, fmt};

use chrono::{DateTime, Utc};
use thiserror::Error;

use crate::model::{
    BoundaryIntegrityCheck, BoundaryLocalRecord, BoundaryModelError, BoundaryReadEvidence,
    BoundaryReadOperation, BoundaryRegistration, BoundaryScope, BoundarySessionResultEvidence,
    BoundarySessionResultProposal, BoundarySessionResultState, Digest, SecretReference,
};
use crate::provider::{BoundaryProvider, BoundaryProviderError};
use crate::transport::BoundaryTransport;
use crate::{
    BOUNDARY_EVIDENCE_POLICY_SCHEMA, BOUNDARY_PLUGIN_VERSION, BOUNDARY_SERVICE_ID,
    BOUNDARY_SERVICE_IMPLEMENTATION, contract_digest,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundaryServiceOperation {
    DescribeCapabilities,
    Register,
    RevokeRegistration,
    ListSessions,
    ReadSession,
    ReadTarget,
    CompileProposal,
    RecordLocal,
    VerifyIntegrity,
}

impl BoundaryServiceOperation {
    pub const ALL: [Self; 9] = [
        Self::DescribeCapabilities,
        Self::Register,
        Self::RevokeRegistration,
        Self::ListSessions,
        Self::ReadSession,
        Self::ReadTarget,
        Self::CompileProposal,
        Self::RecordLocal,
        Self::VerifyIntegrity,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::DescribeCapabilities => "describe_capabilities",
            Self::Register => "register",
            Self::RevokeRegistration => "revoke_registration",
            Self::ListSessions => "list_sessions",
            Self::ReadSession => "read_session",
            Self::ReadTarget => "read_target",
            Self::CompileProposal => "compile_proposal",
            Self::RecordLocal => "record_local",
            Self::VerifyIntegrity => "verify_integrity",
        }
    }

    pub const fn provider_write(self) -> bool {
        false
    }

    pub const fn bounded(self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundaryCapability {
    pub operation: BoundaryServiceOperation,
    pub read_only: bool,
    pub bounded: bool,
    pub provider_write: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum BoundarySessionResultServiceError {
    #[error("Boundary contract error: {0}")]
    Contract(#[from] crate::BoundaryContractError),
    #[error("Boundary model error: {0}")]
    Model(#[from] BoundaryModelError),
    #[error("Boundary provider error: {0}")]
    Provider(#[from] BoundaryProviderError),
    #[error("Boundary registration is revoked")]
    RegistrationRevoked,
    #[error("Boundary registration is stale or drifted: {0}")]
    RegistrationDrift(&'static str),
    #[error("Boundary secret reference is revoked")]
    SecretRevoked,
    #[error("Boundary evidence is stale or tampered")]
    EvidenceTampered,
    #[error("Boundary proposal is stale or tampered")]
    ProposalTampered,
    #[error("Boundary proposal was already recorded")]
    ReplayDetected,
}

pub type BoundaryServiceError = BoundarySessionResultServiceError;

/// The typed Layer-1 Boundary session-result service.
pub struct BoundarySessionResultService<T> {
    scope: BoundaryScope,
    secret: SecretReference,
    provider: BoundaryProvider<T>,
    registration: BoundaryRegistration,
    recorded_proposals: BTreeSet<Digest>,
}

impl<T: BoundaryTransport> fmt::Debug for BoundarySessionResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundarySessionResultService")
            .field("scope", &self.scope)
            .field("secret", &self.secret)
            .field("provider", &self.provider)
            .field("registration", &self.registration)
            .field("recorded_proposals", &self.recorded_proposals.len())
            .finish()
    }
}

impl<T: BoundaryTransport> BoundarySessionResultService<T> {
    pub fn new(
        scope: BoundaryScope,
        secret: SecretReference,
        provider: BoundaryProvider<T>,
    ) -> Result<Self, BoundarySessionResultServiceError> {
        scope.validate()?;
        crate::BoundarySessionResultContract::baseline()?;
        provider
            .definition()
            .validate()
            .map_err(BoundarySessionResultServiceError::Provider)?;
        if provider.permission_digest() != scope.permission_digest() {
            return Err(BoundarySessionResultServiceError::RegistrationDrift(
                "permission digest",
            ));
        }
        let evidence_digest = Digest::from_text(BOUNDARY_EVIDENCE_POLICY_SCHEMA);
        let registration = BoundaryRegistration::new(
            &scope,
            &secret,
            provider.provider_digest(),
            evidence_digest,
            contract_digest(),
        );
        Ok(Self {
            scope,
            secret,
            provider,
            registration,
            recorded_proposals: BTreeSet::new(),
        })
    }

    pub fn register(&mut self) -> Result<&BoundaryRegistration, BoundarySessionResultServiceError> {
        self.ensure_registration()?;
        Ok(&self.registration)
    }

    pub fn scope(&self) -> &BoundaryScope {
        &self.scope
    }

    pub fn secret_reference(&self) -> &SecretReference {
        &self.secret
    }

    pub fn registration(&self) -> &BoundaryRegistration {
        &self.registration
    }

    pub fn registration_mut(&mut self) -> &mut BoundaryRegistration {
        &mut self.registration
    }

    pub fn provider(&self) -> &BoundaryProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut BoundaryProvider<T> {
        &mut self.provider
    }

    pub fn is_active(&self) -> bool {
        self.registration.is_active() && !self.secret.is_revoked()
    }

    pub fn revoke_registration(&mut self) -> Result<(), BoundarySessionResultServiceError> {
        self.registration.revoke()?;
        Ok(())
    }

    pub fn revoke_secret(&mut self) -> Result<(), BoundarySessionResultServiceError> {
        self.secret.revoke()?;
        Ok(())
    }

    pub const fn service_id(&self) -> &'static str {
        BOUNDARY_SERVICE_ID
    }

    pub const fn service_implementation(&self) -> &'static str {
        BOUNDARY_SERVICE_IMPLEMENTATION
    }

    pub const fn version(&self) -> &'static str {
        BOUNDARY_PLUGIN_VERSION
    }

    pub const fn native_connected(&self) -> bool {
        false
    }

    pub const fn native(&self) -> bool {
        false
    }

    pub const fn connected(&self) -> bool {
        false
    }

    pub const fn first_party(&self) -> bool {
        false
    }

    pub fn describe_capabilities(&self) -> Vec<BoundaryCapability> {
        BoundaryServiceOperation::ALL
            .into_iter()
            .map(|operation| BoundaryCapability {
                operation,
                read_only: true,
                bounded: operation.bounded(),
                provider_write: operation.provider_write(),
                native: false,
                connected: false,
                first_party: false,
            })
            .collect()
    }

    pub fn read(
        &mut self,
        operation: BoundaryReadOperation,
        observed_at: DateTime<Utc>,
    ) -> Result<BoundarySessionResultProposal, BoundarySessionResultServiceError> {
        self.ensure_registration()?;
        let evidence = match operation {
            BoundaryReadOperation::ListSessions => {
                self.provider.list_sessions(&self.scope, observed_at)
            }
            BoundaryReadOperation::ReadSession => {
                self.provider.read_session(&self.scope, observed_at)
            }
            BoundaryReadOperation::ReadTarget => {
                self.provider.read_target(&self.scope, observed_at)
            }
        };
        match evidence {
            Ok(evidence) => self.compile_proposal(evidence),
            Err(error) => self.project_provider_failure(operation, error),
        }
    }

    pub fn list_sessions(
        &mut self,
        observed_at: DateTime<Utc>,
    ) -> Result<BoundarySessionResultProposal, BoundarySessionResultServiceError> {
        self.read(BoundaryReadOperation::ListSessions, observed_at)
    }

    pub fn read_session(
        &mut self,
        observed_at: DateTime<Utc>,
    ) -> Result<BoundarySessionResultProposal, BoundarySessionResultServiceError> {
        self.read(BoundaryReadOperation::ReadSession, observed_at)
    }

    pub fn read_target(
        &mut self,
        observed_at: DateTime<Utc>,
    ) -> Result<BoundarySessionResultProposal, BoundarySessionResultServiceError> {
        self.read(BoundaryReadOperation::ReadTarget, observed_at)
    }

    pub fn compile_evidence_proposal(
        &mut self,
        operation: BoundaryReadOperation,
        observed_at: DateTime<Utc>,
    ) -> Result<BoundarySessionResultProposal, BoundarySessionResultServiceError> {
        self.read(operation, observed_at)
    }

    pub fn compile_proposal(
        &self,
        evidence: BoundarySessionResultEvidence,
    ) -> Result<BoundarySessionResultProposal, BoundarySessionResultServiceError> {
        self.ensure_registration()?;
        self.validate_evidence_binding(&evidence)?;
        BoundarySessionResultProposal::new(&self.registration, evidence)
            .map_err(BoundarySessionResultServiceError::Model)
    }

    pub fn record_local(
        &mut self,
        proposal: &BoundarySessionResultProposal,
    ) -> Result<BoundaryLocalRecord, BoundarySessionResultServiceError> {
        self.ensure_registration()?;
        self.validate_proposal_binding(proposal)?;
        if !self
            .recorded_proposals
            .insert(proposal.proposal_digest.clone())
        {
            return Err(BoundarySessionResultServiceError::ReplayDetected);
        }
        Ok(BoundaryLocalRecord {
            recorded: true,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            registration_digest: self.registration.registration_digest.clone(),
            durable_provider_receipt: false,
            provider_mutated: false,
            raw_provider_payload_retained: false,
            credential_material_retained: false,
        })
    }

    pub fn record(
        &mut self,
        proposal: &BoundarySessionResultProposal,
    ) -> Result<BoundaryLocalRecord, BoundarySessionResultServiceError> {
        self.record_local(proposal)
    }

    pub fn verify_integrity(
        &self,
        proposal: &BoundarySessionResultProposal,
    ) -> Result<BoundaryIntegrityCheck, BoundarySessionResultServiceError> {
        self.ensure_registration()?;
        self.validate_proposal_binding(proposal)?;
        proposal
            .validate_integrity()
            .map_err(|_| BoundarySessionResultServiceError::ProposalTampered)?;
        Ok(BoundaryIntegrityCheck {
            valid: true,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            registration_digest: self.registration.registration_digest.clone(),
            provider_readback_performed: false,
            authorization_correctness_authority: false,
            reachability_authority: false,
            consent_authority: false,
            outcome_authority: false,
        })
    }

    pub fn verify(
        &self,
        proposal: &BoundarySessionResultProposal,
    ) -> Result<BoundaryIntegrityCheck, BoundarySessionResultServiceError> {
        self.verify_integrity(proposal)
    }

    fn ensure_registration(&self) -> Result<(), BoundarySessionResultServiceError> {
        self.scope.validate()?;
        self.provider.definition().validate().map_err(|_| {
            BoundarySessionResultServiceError::RegistrationDrift("provider definition")
        })?;
        if !self.registration.is_active() {
            return Err(BoundarySessionResultServiceError::RegistrationRevoked);
        }
        if self.secret.is_revoked() {
            return Err(BoundarySessionResultServiceError::SecretRevoked);
        }
        let expected_evidence_digest = Digest::from_text(BOUNDARY_EVIDENCE_POLICY_SCHEMA);
        self.registration
            .validate(
            &self.scope,
            &self.secret,
            &self.provider.provider_digest(),
            &expected_evidence_digest,
            &contract_digest(),
            )
            .map_err(|_| BoundarySessionResultServiceError::RegistrationDrift(
                "version, contract, provider, permission, scope, secret, evidence, or registration digest",
            ))
    }

    fn validate_evidence_binding(
        &self,
        evidence: &BoundaryReadEvidence,
    ) -> Result<(), BoundarySessionResultServiceError> {
        evidence
            .validate_integrity()
            .map_err(|_| BoundarySessionResultServiceError::EvidenceTampered)?;
        if evidence.scope_digest != *self.scope.scope_digest()
            || evidence.permission_digest != *self.scope.permission_digest()
            || evidence.provider_digest != self.provider.provider_digest()
            || evidence.provider_revision != *self.provider.provider_revision()
            || evidence.contract_digest != contract_digest()
            || evidence.provenance != self.provider.provenance()
        {
            return Err(BoundarySessionResultServiceError::EvidenceTampered);
        }
        Ok(())
    }

    fn validate_proposal_binding(
        &self,
        proposal: &BoundarySessionResultProposal,
    ) -> Result<(), BoundarySessionResultServiceError> {
        if proposal.registration_digest != self.registration.registration_digest
            || proposal.scope_digest != *self.scope.scope_digest()
        {
            return Err(BoundarySessionResultServiceError::ProposalTampered);
        }
        self.validate_evidence_binding(&proposal.evidence)
    }

    fn project_provider_failure(
        &self,
        operation: BoundaryReadOperation,
        error: BoundaryProviderError,
    ) -> Result<BoundarySessionResultProposal, BoundarySessionResultServiceError> {
        let state = if error.is_access_lost() {
            BoundarySessionResultState::AccessLost
        } else if error.is_partial() {
            BoundarySessionResultState::Partial
        } else if error.is_provider_unknown()
            || matches!(error, BoundaryProviderError::LifecycleRegression)
        {
            if matches!(error, BoundaryProviderError::LifecycleRegression) {
                BoundarySessionResultState::Tampered
            } else {
                BoundarySessionResultState::ProviderUnknown
            }
        } else {
            return Err(BoundarySessionResultServiceError::Provider(error));
        };
        let evidence = BoundaryReadEvidence::failure(
            operation,
            state,
            self.scope.scope_digest().clone(),
            self.scope.permission_digest().clone(),
            self.provider.provider_digest(),
            self.provider.provider_revision().to_owned(),
            contract_digest(),
            self.provider.provenance(),
        );
        self.compile_proposal(evidence)
    }
}

pub type BoundaryService<T> = BoundarySessionResultService<T>;
