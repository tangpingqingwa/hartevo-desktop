use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    Digest, INTUNE_DEVICE_COMPLIANCE_RESULT_PLUGIN_VERSION, INTUNE_GRAPH_API_VERSION,
    INTUNE_GRAPH_PROVIDER_ID, INTUNE_GRAPH_PROVIDER_VERSION, IntuneEvidence, IntuneGraphTransport,
    IntuneProvider, IntuneReadRequest, IntuneRegistration, Layer1Authority, ModelError,
    ProviderProvenance, RegistrationBinding, RegistrationState, SecretReference, contract_digest,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct IntuneDeviceComplianceServiceDefinition {
    pub read_only: bool,
    pub live_execution: bool,
    pub external_writes: bool,
    pub certification: bool,
    pub outcome_authority: bool,
}

impl Default for IntuneDeviceComplianceServiceDefinition {
    fn default() -> Self {
        Self {
            read_only: true,
            live_execution: false,
            external_writes: false,
            certification: false,
            outcome_authority: false,
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum IntuneDeviceComplianceServiceError {
    #[error("registration has been revoked")]
    RegistrationRevoked,
    #[error("proposal is outside the registered scope")]
    ScopeMismatch,
    #[error("proposal digest or evidence digest does not match immutable fields")]
    DigestMismatch,
    #[error("proposal has already been recorded")]
    AlreadyRecorded,
    #[error("registration is already revoked")]
    AlreadyRevoked,
    #[error("model validation failed: {0}")]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IntuneComplianceProposal {
    pub evidence: IntuneEvidence,
    pub registration: IntuneRegistration,
    pub proposal_digest: Digest,
    pub authority: Layer1Authority,
}

impl IntuneComplianceProposal {
    #[must_use]
    pub fn status(&self) -> crate::EvidenceStatus {
        self.evidence.status
    }

    #[must_use]
    pub fn summary(&self) -> &crate::ComplianceSummary {
        &self.evidence.summary
    }

    #[must_use]
    pub fn connected(&self) -> bool {
        self.authority.connected
    }

    #[must_use]
    pub fn native(&self) -> bool {
        self.authority.native_provider
    }

    #[must_use]
    pub fn first_party(&self) -> bool {
        self.authority.first_party
    }

    #[must_use]
    pub fn certification(&self) -> bool {
        self.authority.certification
    }

    #[must_use]
    pub fn outcome_authority(&self) -> bool {
        self.authority.outcome_authority
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IntuneVerification {
    pub valid: bool,
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub authority: Layer1Authority,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IntuneObservationReceipt {
    pub proposal_digest: Digest,
    pub evidence_digest: Digest,
    pub registration_digest: Digest,
    pub recorded: bool,
    pub durable_provider_receipt: bool,
    pub independent_readback: bool,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

#[derive(Debug)]
pub struct IntuneDeviceComplianceService<T: IntuneGraphTransport> {
    provider: IntuneProvider<T>,
    registration: IntuneRegistration,
    recorded_proposals: BTreeSet<Digest>,
}

pub type IntuneDeviceComplianceResultService<T> = IntuneDeviceComplianceService<T>;

impl<T: IntuneGraphTransport> IntuneDeviceComplianceService<T> {
    pub fn new(provider: IntuneProvider<T>) -> Result<Self, IntuneDeviceComplianceServiceError> {
        let scope = provider.scope().clone();
        let registration = IntuneRegistration::active(RegistrationBinding {
            provider_digest: provider.definition().digest(),
            provider_api_version: INTUNE_GRAPH_API_VERSION.to_owned(),
            contract_digest: contract_digest(),
            plugin_version: INTUNE_DEVICE_COMPLIANCE_RESULT_PLUGIN_VERSION.to_owned(),
            permission_digest: scope.permission_digest.clone(),
            scope_digest: scope.scope_digest(),
            evidence_digest: Digest::from_text("unobserved-evidence"),
        });
        Ok(Self {
            provider,
            registration,
            recorded_proposals: BTreeSet::new(),
        })
    }

    #[must_use]
    pub const fn definition() -> IntuneDeviceComplianceServiceDefinition {
        IntuneDeviceComplianceServiceDefinition {
            read_only: true,
            live_execution: false,
            external_writes: false,
            certification: false,
            outcome_authority: false,
        }
    }

    pub fn read(
        &mut self,
        request: &IntuneReadRequest,
    ) -> Result<IntuneEvidence, IntuneDeviceComplianceServiceError> {
        self.ensure_active()?;
        if request.scope().scope_digest() != self.provider.scope().scope_digest() {
            return Err(IntuneDeviceComplianceServiceError::ScopeMismatch);
        }
        Ok(self.provider.read(request))
    }

    pub fn propose(
        &mut self,
        request: &IntuneReadRequest,
    ) -> Result<IntuneComplianceProposal, IntuneDeviceComplianceServiceError> {
        let evidence = self.read(request)?;
        let evidence_digest = evidence.digest();
        self.registration = IntuneRegistration::active(RegistrationBinding {
            provider_digest: self.provider.definition().digest(),
            provider_api_version: INTUNE_GRAPH_API_VERSION.to_owned(),
            contract_digest: contract_digest(),
            plugin_version: INTUNE_DEVICE_COMPLIANCE_RESULT_PLUGIN_VERSION.to_owned(),
            permission_digest: self.provider.scope().permission_digest.clone(),
            scope_digest: self.provider.scope().scope_digest(),
            evidence_digest,
        });
        let proposal_digest = proposal_digest(&evidence, &self.registration);
        Ok(IntuneComplianceProposal {
            evidence,
            registration: self.registration.clone(),
            proposal_digest,
            authority: Layer1Authority::layer1(),
        })
    }

    pub fn verify(
        &self,
        proposal: &IntuneComplianceProposal,
    ) -> Result<IntuneVerification, IntuneDeviceComplianceServiceError> {
        self.ensure_active()?;
        if proposal.registration != self.registration {
            return Err(IntuneDeviceComplianceServiceError::DigestMismatch);
        }
        if proposal.evidence.scope_digest != self.provider.scope().scope_digest()
            || proposal.evidence.revision_fence != self.provider.scope().revision_fence()
            || proposal.registration.binding.scope_digest != self.provider.scope().scope_digest()
            || proposal.registration.binding.provider_digest != self.provider.definition().digest()
            || proposal.registration.binding.provider_api_version != INTUNE_GRAPH_API_VERSION
            || proposal.registration.binding.contract_digest != contract_digest()
            || proposal.registration.binding.plugin_version
                != INTUNE_DEVICE_COMPLIANCE_RESULT_PLUGIN_VERSION
        {
            return Err(IntuneDeviceComplianceServiceError::ScopeMismatch);
        }
        let evidence_digest = proposal.evidence.digest();
        if proposal.registration.binding.evidence_digest != evidence_digest
            || proposal.proposal_digest
                != proposal_digest(&proposal.evidence, &proposal.registration)
        {
            return Err(IntuneDeviceComplianceServiceError::DigestMismatch);
        }
        if proposal.authority != Layer1Authority::layer1()
            || proposal.evidence.authority != Layer1Authority::layer1()
        {
            return Err(IntuneDeviceComplianceServiceError::DigestMismatch);
        }
        Ok(IntuneVerification {
            valid: true,
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest,
            registration_digest: proposal.registration.registration_digest.clone(),
            authority: Layer1Authority::layer1(),
        })
    }

    pub fn record(
        &mut self,
        proposal: &IntuneComplianceProposal,
    ) -> Result<IntuneObservationReceipt, IntuneDeviceComplianceServiceError> {
        let _verification = self.verify(proposal)?;
        if !self
            .recorded_proposals
            .insert(proposal.proposal_digest.clone())
        {
            return Err(IntuneDeviceComplianceServiceError::AlreadyRecorded);
        }
        Ok(IntuneObservationReceipt {
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.digest(),
            registration_digest: proposal.registration.registration_digest.clone(),
            recorded: true,
            durable_provider_receipt: false,
            independent_readback: false,
            connected: false,
            native: false,
            first_party: false,
        })
    }

    pub fn revoke_registration(
        &mut self,
        reason: impl AsRef<str>,
    ) -> Result<(), IntuneDeviceComplianceServiceError> {
        self.registration
            .revoke(reason)
            .map_err(|error| match error {
                ModelError::AlreadyRevoked => IntuneDeviceComplianceServiceError::AlreadyRevoked,
                error => IntuneDeviceComplianceServiceError::Model(error),
            })
    }

    #[must_use]
    pub fn registration(&self) -> &IntuneRegistration {
        &self.registration
    }

    #[must_use]
    pub fn provider(&self) -> &IntuneProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn provider_mut(&mut self) -> &mut IntuneProvider<T> {
        &mut self.provider
    }

    fn ensure_active(&self) -> Result<(), IntuneDeviceComplianceServiceError> {
        if self.registration.state == RegistrationState::Revoked {
            Err(IntuneDeviceComplianceServiceError::RegistrationRevoked)
        } else {
            Ok(())
        }
    }
}

fn proposal_digest(evidence: &IntuneEvidence, registration: &IntuneRegistration) -> Digest {
    Digest::from_fields(
        "intune.proposal.v1",
        &[
            evidence.digest().as_str().to_owned(),
            registration.registration_digest.as_str().to_owned(),
        ],
    )
}

#[allow(dead_code)]
fn _provider_identity() -> (&'static str, &'static str, &'static str) {
    (
        INTUNE_GRAPH_PROVIDER_ID,
        INTUNE_GRAPH_PROVIDER_VERSION,
        INTUNE_GRAPH_API_VERSION,
    )
}

#[allow(dead_code)]
fn _secret_type_is_opaque(_: &SecretReference, _: ProviderProvenance) {}
