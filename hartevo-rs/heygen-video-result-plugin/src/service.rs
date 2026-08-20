use std::collections::BTreeSet;

use thiserror::Error;

use crate::{
    consumer::{AdoptionProposal, ConsumerError, MissionVideoResultConsumer},
    provider::{
        ArtifactReceipt, Capability, CapabilityProbeReceipt, HeyGenVideoProvider, HttpsTransport,
        IdentityProbeReceipt, OperationReceipt, ProviderError, TemplateProbeReceipt,
    },
    registration::{HeyGenVideoResultRegistration, RegistrationError},
    types::{Digest, GenerationProposal, GenerationStatusProjection, MissionVideoSource},
};

/// Service-level errors; the provider and Mission consumer retain their own
/// typed failures at their boundaries.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum ServiceError {
    #[error("registration error: {0}")]
    Registration(#[from] RegistrationError),
    #[error("provider error: {0}")]
    Provider(#[from] ProviderError),
    #[error("consumer error: {0}")]
    Consumer(#[from] ConsumerError),
    #[error("generation proposal fingerprint already exists")]
    DuplicateProposal,
}

/// Typed HeyGen video-result service. It composes proposals and delegates
/// read/recorded receipts; it has no live side effects.
pub struct HeyGenVideoResultService {
    registration: HeyGenVideoResultRegistration,
    proposal_fingerprints: BTreeSet<Digest>,
}

impl HeyGenVideoResultService {
    pub fn new(registration: HeyGenVideoResultRegistration) -> Result<Self, ServiceError> {
        registration.ensure_active()?;
        Ok(Self {
            registration,
            proposal_fingerprints: BTreeSet::new(),
        })
    }

    pub fn registration(&self) -> &HeyGenVideoResultRegistration {
        &self.registration
    }

    pub fn propose_generation<T: HttpsTransport>(
        &mut self,
        provider: &HeyGenVideoProvider<T>,
        source: &MissionVideoSource,
    ) -> Result<GenerationProposal, ServiceError> {
        self.registration.ensure_active()?;
        self.registration.ensure_scope(source.scope())?;
        if provider.registration().registration_digest() != self.registration.registration_digest()
        {
            return Err(ServiceError::Registration(RegistrationError::ScopeMismatch));
        }
        let proposal = provider.propose_generation(source)?;
        if !self
            .proposal_fingerprints
            .insert(proposal.fence().fingerprint().clone())
        {
            return Err(ServiceError::DuplicateProposal);
        }
        Ok(proposal)
    }

    pub fn probe_capability<T: HttpsTransport>(
        &self,
        provider: &mut HeyGenVideoProvider<T>,
        capability: Capability,
        observed_at: u64,
    ) -> Result<CapabilityProbeReceipt, ServiceError> {
        self.ensure_provider(provider)?;
        Ok(provider.probe_capability(capability, observed_at)?)
    }

    pub fn probe_template<T: HttpsTransport>(
        &self,
        provider: &mut HeyGenVideoProvider<T>,
        template_id: crate::TemplateId,
        observed_at: u64,
    ) -> Result<TemplateProbeReceipt, ServiceError> {
        self.ensure_provider(provider)?;
        Ok(provider.probe_template(template_id, observed_at)?)
    }

    pub fn probe_avatar<T: HttpsTransport>(
        &self,
        provider: &mut HeyGenVideoProvider<T>,
        avatar_id: crate::AvatarId,
        consent: Option<&crate::ConsentReference>,
        observed_at: u64,
    ) -> Result<IdentityProbeReceipt, ServiceError> {
        self.ensure_provider(provider)?;
        Ok(provider.probe_avatar(avatar_id, consent, observed_at)?)
    }

    pub fn probe_voice<T: HttpsTransport>(
        &self,
        provider: &mut HeyGenVideoProvider<T>,
        voice_id: crate::VoiceId,
        consent: Option<&crate::ConsentReference>,
        observed_at: u64,
    ) -> Result<IdentityProbeReceipt, ServiceError> {
        self.ensure_provider(provider)?;
        Ok(provider.probe_voice(voice_id, consent, observed_at)?)
    }

    pub fn record_status<T: HttpsTransport>(
        &self,
        provider: &HeyGenVideoProvider<T>,
        receipt: OperationReceipt,
    ) -> Result<OperationReceipt, ServiceError> {
        self.ensure_provider(provider)?;
        Ok(provider.record_status(receipt)?)
    }

    pub fn record_artifact<T: HttpsTransport>(
        &self,
        provider: &HeyGenVideoProvider<T>,
        receipt: ArtifactReceipt,
    ) -> Result<ArtifactReceipt, ServiceError> {
        self.ensure_provider(provider)?;
        Ok(provider.record_artifact(receipt)?)
    }

    pub fn project_status(
        &self,
        consumer: &mut MissionVideoResultConsumer,
        receipt: &OperationReceipt,
    ) -> Result<GenerationStatusProjection, ServiceError> {
        self.registration.ensure_active()?;
        if consumer.registration().registration_digest() != self.registration.registration_digest()
        {
            return Err(ServiceError::Registration(RegistrationError::ScopeMismatch));
        }
        Ok(consumer.project_status(receipt)?)
    }

    pub fn propose_adoption(
        &self,
        consumer: &mut MissionVideoResultConsumer,
        proposal: &GenerationProposal,
        status: &OperationReceipt,
        artifact: &ArtifactReceipt,
        now: u64,
    ) -> Result<AdoptionProposal, ServiceError> {
        self.registration.ensure_active()?;
        if consumer.registration().registration_digest() != self.registration.registration_digest()
        {
            return Err(ServiceError::Registration(RegistrationError::ScopeMismatch));
        }
        Ok(consumer.propose_adoption(proposal, status, artifact, now)?)
    }

    fn ensure_provider<T: HttpsTransport>(
        &self,
        provider: &HeyGenVideoProvider<T>,
    ) -> Result<(), ServiceError> {
        self.registration.ensure_active()?;
        if provider.registration().registration_digest() != self.registration.registration_digest()
        {
            return Err(ServiceError::Registration(RegistrationError::ScopeMismatch));
        }
        Ok(())
    }
}

impl std::fmt::Debug for HeyGenVideoResultService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HeyGenVideoResultService")
            .field("registration", &self.registration)
            .field("proposal_count", &self.proposal_fingerprints.len())
            .finish()
    }
}
