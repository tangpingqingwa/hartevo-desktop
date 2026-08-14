use std::collections::BTreeSet;

use thiserror::Error;

use crate::{
    consumer::{AudioWorkProductProposal, ConsumerError, MissionAudioResultConsumer},
    provider::{
        AudioStatusProjection, ElevenLabsProvider, HttpsTransport, ProviderError, SynthesisReceipt,
    },
    registration::{ElevenLabsAudioResultRegistration, RegistrationError},
    types::{AudioCreationObjective, AudioGenerationProposal, Digest},
};

/// Service-level errors; provider and Mission consumer retain their own typed
/// failures at their boundaries.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum ServiceError {
    #[error("registration error: {0}")]
    Registration(#[from] RegistrationError),
    #[error("provider error: {0}")]
    Provider(#[from] ProviderError),
    #[error("consumer error: {0}")]
    Consumer(#[from] ConsumerError),
    #[error("audio proposal fingerprint already exists")]
    DuplicateProposal,
}

/// Typed ElevenLabs audio-result service. It composes proposals and delegates
/// recorded receipts; it has no live side effects.
pub struct ElevenLabsAudioResultService {
    registration: ElevenLabsAudioResultRegistration,
    proposal_fingerprints: BTreeSet<Digest>,
}

impl ElevenLabsAudioResultService {
    pub fn new(registration: ElevenLabsAudioResultRegistration) -> Result<Self, ServiceError> {
        registration.ensure_active()?;
        if !registration.verify_digest() {
            return Err(ServiceError::Registration(RegistrationError::InvalidDigest));
        }
        Ok(Self {
            registration,
            proposal_fingerprints: BTreeSet::new(),
        })
    }

    pub fn registration(&self) -> &ElevenLabsAudioResultRegistration {
        &self.registration
    }

    pub fn propose_audio<T: HttpsTransport>(
        &mut self,
        provider: &ElevenLabsProvider<T>,
        objective: &AudioCreationObjective,
    ) -> Result<AudioGenerationProposal, ServiceError> {
        self.ensure_provider(provider)?;
        self.registration.ensure_scope(objective.scope())?;
        let proposal = provider.propose_audio(objective)?;
        if !self
            .proposal_fingerprints
            .insert(proposal.fence().fingerprint().clone())
        {
            return Err(ServiceError::DuplicateProposal);
        }
        Ok(proposal)
    }

    pub fn propose_generation<T: HttpsTransport>(
        &mut self,
        provider: &ElevenLabsProvider<T>,
        objective: &AudioCreationObjective,
    ) -> Result<AudioGenerationProposal, ServiceError> {
        self.propose_audio(provider, objective)
    }

    pub fn record_synthesis<T: HttpsTransport>(
        &self,
        provider: &mut ElevenLabsProvider<T>,
        proposal: &AudioGenerationProposal,
    ) -> Result<SynthesisReceipt, ServiceError> {
        self.ensure_provider(provider)?;
        Ok(provider.record_synthesis(proposal)?)
    }

    pub fn record_status<T: HttpsTransport>(
        &self,
        provider: &ElevenLabsProvider<T>,
        proposal: &AudioGenerationProposal,
        receipt: SynthesisReceipt,
    ) -> Result<SynthesisReceipt, ServiceError> {
        self.ensure_provider(provider)?;
        Ok(provider.record_status(proposal, receipt)?)
    }

    pub fn project_status(
        &self,
        consumer: &mut MissionAudioResultConsumer,
        receipt: &SynthesisReceipt,
    ) -> Result<AudioStatusProjection, ServiceError> {
        self.ensure_consumer(consumer)?;
        Ok(consumer.project_status(receipt)?)
    }

    pub fn propose_work_product(
        &self,
        consumer: &mut MissionAudioResultConsumer,
        proposal: &AudioGenerationProposal,
        receipt: &SynthesisReceipt,
    ) -> Result<AudioWorkProductProposal, ServiceError> {
        self.ensure_consumer(consumer)?;
        Ok(consumer.propose_work_product(proposal, receipt)?)
    }

    pub fn propose_adoption(
        &self,
        consumer: &mut MissionAudioResultConsumer,
        proposal: &AudioGenerationProposal,
        receipt: &SynthesisReceipt,
    ) -> Result<AudioWorkProductProposal, ServiceError> {
        self.propose_work_product(consumer, proposal, receipt)
    }

    fn ensure_provider<T: HttpsTransport>(
        &self,
        provider: &ElevenLabsProvider<T>,
    ) -> Result<(), ServiceError> {
        self.registration.ensure_active()?;
        if !self.registration.verify_digest()
            || !provider.registration().verify_digest()
            || provider.registration().registration_digest()
                != self.registration.registration_digest()
        {
            return Err(ServiceError::Registration(RegistrationError::ScopeMismatch));
        }
        Ok(())
    }

    fn ensure_consumer(&self, consumer: &MissionAudioResultConsumer) -> Result<(), ServiceError> {
        self.registration.ensure_active()?;
        if !self.registration.verify_digest()
            || !consumer.registration().verify_digest()
            || consumer.registration().registration_digest()
                != self.registration.registration_digest()
        {
            return Err(ServiceError::Registration(RegistrationError::ScopeMismatch));
        }
        Ok(())
    }
}

impl std::fmt::Debug for ElevenLabsAudioResultService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ElevenLabsAudioResultService")
            .field("registration", &self.registration)
            .field("proposal_count", &self.proposal_fingerprints.len())
            .finish()
    }
}
