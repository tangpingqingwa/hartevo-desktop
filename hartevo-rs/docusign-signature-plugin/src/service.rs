use std::fmt;

use thiserror::Error;

use crate::provider::PollPlan;
use crate::{
    ConsumerError, Digest, DocuSignHttpRequest, DocuSignReceipt, EnvelopeProposal,
    EnvelopeProposalRequest, EnvelopeStatusProjection, MissionSignedResultConsumer, ModelError,
    NativeOperation, ProviderAvailability, ProviderError, RecipientStatusProjection,
    RecordedEnvelopeObservation, SignatureProvider, SignedResultAdoptionProposal,
    SignedResultSource,
};

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ServiceError {
    #[error("DocuSign service request scope does not match the provider scope")]
    ScopeMismatch,
    #[error("DocuSign service model rejected the proposal: {0}")]
    Model(#[from] ModelError),
    #[error("DocuSign provider rejected the recording: {0}")]
    Provider(#[from] ProviderError),
    #[error("DocuSign Mission consumer rejected adoption: {0}")]
    Consumer(#[from] ConsumerError),
}

pub struct DocuSignSignatureService<P> {
    provider: P,
    consumer: MissionSignedResultConsumer,
}

impl<P> fmt::Debug for DocuSignSignatureService<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DocuSignSignatureService")
            .field("scope_digest", &self.consumer.scope().digest())
            .field("provider_version", &self.consumer.provider_version())
            .field("registration_digest", &self.consumer.registration_digest())
            .field("current_revision", &self.consumer.current_revision())
            .finish_non_exhaustive()
    }
}

impl<P: SignatureProvider> DocuSignSignatureService<P> {
    pub fn new(provider: P, current_revision: crate::RevisionFence) -> Result<Self, ServiceError> {
        let consumer = MissionSignedResultConsumer::new(
            provider.scope().clone(),
            current_revision,
            provider.provider_version(),
            provider.registration_digest().clone(),
        )?;
        Ok(Self { provider, consumer })
    }

    pub fn provider(&self) -> &P {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut P {
        &mut self.provider
    }

    pub fn consumer(&self) -> &MissionSignedResultConsumer {
        &self.consumer
    }

    pub fn propose_envelope(
        &self,
        request: EnvelopeProposalRequest,
    ) -> Result<EnvelopeProposal, ServiceError> {
        if request.scope() != self.provider.scope() {
            return Err(ServiceError::ScopeMismatch);
        }
        EnvelopeProposal::from_request(
            request,
            self.provider.provider_version(),
            self.provider.registration_digest().clone(),
        )
        .map_err(ServiceError::from)
    }

    pub fn project_receipt(
        &mut self,
        proposal: &EnvelopeProposal,
        observation: &RecordedEnvelopeObservation,
    ) -> Result<DocuSignReceipt, ServiceError> {
        self.provider
            .record_receipt(proposal, observation)
            .map_err(ServiceError::from)
    }

    pub fn project_envelope_status(
        &self,
        receipt: &DocuSignReceipt,
    ) -> Result<EnvelopeStatusProjection, ServiceError> {
        self.validate_receipt(receipt)?;
        Ok(receipt.envelope_status_projection())
    }

    pub fn project_recipient_statuses<'a>(
        &self,
        receipt: &'a DocuSignReceipt,
    ) -> Result<&'a [RecipientStatusProjection], ServiceError> {
        self.validate_receipt(receipt)?;
        Ok(receipt.recipient_status_projection())
    }

    pub fn propose_signed_result_adoption(
        &self,
        receipt: &DocuSignReceipt,
        source: &SignedResultSource,
    ) -> Result<SignedResultAdoptionProposal, ServiceError> {
        self.consumer
            .propose_adoption(receipt, source)
            .map_err(ServiceError::from)
    }

    pub fn availability(&self) -> ProviderAvailability {
        self.provider.availability()
    }

    pub fn poll_plan(&self) -> PollPlan {
        self.provider.poll_plan()
    }

    pub fn prepare_layer2_request(
        &self,
        operation: NativeOperation,
        request_digest: Digest,
    ) -> DocuSignHttpRequest {
        self.provider
            .prepare_layer2_request(operation, request_digest)
    }

    fn validate_receipt(&self, receipt: &DocuSignReceipt) -> Result<(), ServiceError> {
        receipt
            .validate_integrity()
            .map_err(|_| ServiceError::Consumer(ConsumerError::TamperedReceipt))?;
        if receipt.scope_digest() != &self.provider.scope().digest() {
            return Err(ServiceError::Consumer(ConsumerError::ScopeMismatch));
        }
        if receipt.provider_version() != self.provider.provider_version()
            || receipt.registration_digest() != self.provider.registration_digest()
        {
            return Err(ServiceError::Consumer(ConsumerError::RegistrationMismatch));
        }
        Ok(())
    }
}
