use std::fmt;

use crate::{
    CONSUMER_ID, PROVIDER_ID, SERVICE_ID,
    error::{Result, TinesAutomationResultError},
    model::{
        RegistrationRevocationReceipt, TinesAutomationEvidence, TinesAutomationProposal,
        TinesAutomationScope, TinesObservationReceipt, TinesReadbackReceipt, TinesRegistration,
    },
    provider::{TinesProvider, TinesTransport},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TinesAutomationResultServiceDefinition {
    pub id: &'static str,
    pub version: &'static str,
    pub read_only: bool,
    pub external_writes: bool,
    pub kernel_authority: bool,
    pub outcome_authority: bool,
}

impl TinesAutomationResultServiceDefinition {
    pub const fn current() -> Self {
        Self {
            id: SERVICE_ID,
            version: crate::SERVICE_VERSION,
            read_only: true,
            external_writes: false,
            kernel_authority: false,
            outcome_authority: false,
        }
    }
}

pub type TinesAutomationResultServiceError = TinesAutomationResultError;
pub type TinesServiceError = TinesAutomationResultError;

/// Layer-1 service for bounded Tines automation evidence. It only compiles
/// read-only provider observations into a proposal; it cannot trigger a
/// story, mutate an action/case, create a durable receipt, or adopt Outcome.
pub struct TinesAutomationResultService<T> {
    provider: TinesProvider<T>,
}

impl<T: TinesTransport> fmt::Debug for TinesAutomationResultService<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TinesAutomationResultService")
            .field("scope_digest", &self.provider.scope().digest())
            .field(
                "registration_digest",
                &self.provider.registration().registration_digest,
            )
            .field("provider", &self.provider)
            .finish()
    }
}

impl<T: TinesTransport> TinesAutomationResultService<T> {
    pub fn new(
        scope: TinesAutomationScope,
        secret: crate::SecretReference,
        transport: T,
    ) -> Result<Self> {
        Ok(Self {
            provider: TinesProvider::new(scope, secret, transport)?,
        })
    }

    pub fn from_provider(provider: TinesProvider<T>) -> Self {
        Self { provider }
    }

    #[must_use]
    pub const fn definition() -> TinesAutomationResultServiceDefinition {
        TinesAutomationResultServiceDefinition::current()
    }

    #[must_use]
    pub fn provider(&self) -> &TinesProvider<T> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut TinesProvider<T> {
        &mut self.provider
    }

    #[must_use]
    pub fn scope(&self) -> &TinesAutomationScope {
        self.provider.scope()
    }

    #[must_use]
    pub fn registration(&self) -> &TinesRegistration {
        self.provider.registration()
    }

    pub fn read(&mut self) -> Result<TinesAutomationEvidence> {
        self.provider.read()
    }

    pub fn validate_consent(&self, consent: &crate::ConsentScope) -> Result<()> {
        consent.validate_at(chrono::Utc::now())?;
        if consent.digest() == self.scope().consent().digest() {
            Ok(())
        } else {
            Err(TinesAutomationResultError::ConsentMismatch)
        }
    }

    pub fn compile_proposal(&mut self) -> Result<TinesAutomationProposal> {
        let evidence = self.read()?;
        self.compile_proposal_from_evidence(evidence)
    }

    pub fn compile_proposal_from_evidence(
        &self,
        evidence: TinesAutomationEvidence,
    ) -> Result<TinesAutomationProposal> {
        self.ensure_registration()?;
        evidence.validate_integrity(self.scope(), self.provider.provider_digest())?;
        Ok(TinesAutomationProposal {
            service_id: SERVICE_ID.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            consumer_id: CONSUMER_ID.to_owned(),
            contract_digest: crate::contract_digest(),
            registration_digest: self.registration().registration_digest.clone(),
            scope_digest: self.scope().digest(),
            project: self.scope().project().clone(),
            mission: self.scope().mission().clone(),
            work_product: self.scope().work_product().clone(),
            state: evidence.state,
            evidence,
            review_only: true,
            non_mutating: true,
            claims_external_side_effect: false,
            claims_remediation_success: false,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            outcome_adopted: false,
            work_product_adopted: false,
            proposal_digest: String::new(),
        }
        .seal())
    }

    pub fn verify_proposal(&self, proposal: &TinesAutomationProposal) -> Result<()> {
        self.ensure_registration()?;
        if proposal.service_id != SERVICE_ID
            || proposal.provider_id != PROVIDER_ID
            || proposal.consumer_id != CONSUMER_ID
        {
            return Err(TinesAutomationResultError::ScopeMismatch);
        }
        proposal.validate_integrity(self.scope(), self.registration())?;
        proposal
            .evidence
            .validate_integrity(self.scope(), self.provider.provider_digest())
    }

    pub fn record_observation(
        &self,
        proposal: &TinesAutomationProposal,
    ) -> Result<TinesObservationReceipt> {
        self.verify_proposal(proposal)?;
        Ok(TinesObservationReceipt {
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            registration_digest: proposal.registration_digest.clone(),
            recorded: true,
            durable: false,
            provider_receipt: false,
            independent_native_readback: false,
            connected: false,
            native: false,
            first_party: false,
        })
    }

    pub fn read_back(&self, proposal: &TinesAutomationProposal) -> Result<TinesReadbackReceipt> {
        self.verify_proposal(proposal)?;
        Ok(TinesReadbackReceipt {
            proposal_digest: proposal.proposal_digest.clone(),
            evidence_digest: proposal.evidence.evidence_digest.clone(),
            status: "verified_against_layer1_proposal".to_owned(),
            independent_native_readback: false,
            provider_receipt: false,
            connected: false,
            native: false,
            first_party: false,
        })
    }

    pub fn revoke(&mut self) -> Result<RegistrationRevocationReceipt> {
        self.provider.revoke()
    }

    pub fn restore(&mut self) -> Result<RegistrationRevocationReceipt> {
        self.provider.restore()
    }

    fn ensure_registration(&self) -> Result<()> {
        self.registration().validate(
            self.scope(),
            self.provider.secret_reference(),
            self.provider.provider_digest(),
        )
    }
}
