use crate::error::TwilioHandoffError;
use crate::model::SecretMaterial;
use crate::model::{
    DeliveryStatusProjection, DeliveryStatusRequest, HandoffProposal, HandoffProposalRequest,
    ReceiptReadRequest, TwilioCallbackRequest, TwilioMessageReceipt, VerifiedInboundSignal,
};
use crate::provider::TwilioHandoffProvider;
use crate::registration::TwilioHandoffRegistration;

/// Typed Layer 1 service surface.  Each operation is explicit and returns a
/// typed value; there is no generic JSON command or mutation method.
#[derive(Clone, Debug)]
pub struct TwilioHandoffService {
    registration: TwilioHandoffRegistration,
}

impl TwilioHandoffService {
    pub fn new(registration: TwilioHandoffRegistration) -> Result<Self, TwilioHandoffError> {
        registration.validate()?;
        Ok(Self { registration })
    }

    pub fn registration(&self) -> &TwilioHandoffRegistration {
        &self.registration
    }

    pub fn propose(
        &self,
        request: HandoffProposalRequest,
    ) -> Result<HandoffProposal, TwilioHandoffError> {
        self.ensure_active()?;
        if request.scope != self.registration.scope {
            return Err(TwilioHandoffError::ScopeMismatch);
        }
        HandoffProposal::build(
            request,
            crate::TWILIO_HANDOFF_PROVIDER_ID,
            self.registration.plugin_version,
            self.registration.registration_digest.clone(),
        )
    }

    pub fn record_receipt(
        &self,
        provider: &TwilioHandoffProvider,
        proposal: &HandoffProposal,
        observed_at_ms: u64,
    ) -> Result<TwilioMessageReceipt, TwilioHandoffError> {
        self.ensure_provider(provider)?;
        provider.record_proposal(proposal, observed_at_ms)
    }

    pub fn read_receipt(
        &self,
        provider: &TwilioHandoffProvider,
        request: &ReceiptReadRequest,
    ) -> Result<TwilioMessageReceipt, TwilioHandoffError> {
        self.ensure_provider(provider)?;
        provider.read_receipt(request)
    }

    pub fn project_delivery_status(
        &self,
        provider: &TwilioHandoffProvider,
        request: &DeliveryStatusRequest,
    ) -> Result<DeliveryStatusProjection, TwilioHandoffError> {
        self.ensure_provider(provider)?;
        provider.project_delivery_status(request)
    }

    pub fn verify_inbound_signal(
        &self,
        provider: &TwilioHandoffProvider,
        callback: &TwilioCallbackRequest,
        auth_token: &SecretMaterial,
    ) -> Result<VerifiedInboundSignal, TwilioHandoffError> {
        self.ensure_provider(provider)?;
        provider.verify_inbound_signal(callback, auth_token)
    }

    fn ensure_active(&self) -> Result<(), TwilioHandoffError> {
        self.registration.validate()?;
        if !self.registration.is_active() {
            return Err(TwilioHandoffError::RegistrationRevoked);
        }
        Ok(())
    }

    fn ensure_provider(&self, provider: &TwilioHandoffProvider) -> Result<(), TwilioHandoffError> {
        self.ensure_active()?;
        if provider.registration().registration_digest() != self.registration.registration_digest()
            || provider.scope() != &self.registration.scope
        {
            return Err(TwilioHandoffError::ScopeMismatch);
        }
        Ok(())
    }
}
