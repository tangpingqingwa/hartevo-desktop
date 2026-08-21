//! Service façade exposing only bounded describe/read/proposal/record/verify
//! operations.

use std::fmt;

use crate::RampSpendOutcomeError;
use crate::model::{
    Capabilities, DateWindow, EvidenceReceipt, EvidenceVerification, OutcomeProposal, SpendEvidence,
};
use crate::provider::RampProvider;
use crate::transport::RampTransport;

pub struct RampSpendOutcomeService<T = crate::BlockedEnvRampTransport>
where
    T: RampTransport,
{
    provider: RampProvider<T>,
}

impl<T> fmt::Debug for RampSpendOutcomeService<T>
where
    T: RampTransport,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RampSpendOutcomeService")
            .field("provider", &self.provider)
            .finish()
    }
}

impl<T> RampSpendOutcomeService<T>
where
    T: RampTransport,
{
    #[must_use]
    pub fn new(provider: RampProvider<T>) -> Self {
        Self { provider }
    }

    #[must_use]
    pub fn provider(&self) -> &RampProvider<T> {
        &self.provider
    }

    #[must_use]
    pub fn describe_capabilities(&self) -> Capabilities {
        self.provider.capabilities()
    }

    pub fn read_spend_evidence(
        &self,
        window: DateWindow,
    ) -> Result<SpendEvidence, RampSpendOutcomeError> {
        self.provider.read_evidence(window)
    }

    pub fn compile_outcome_proposal(
        &self,
        evidence: &SpendEvidence,
    ) -> Result<OutcomeProposal, RampSpendOutcomeError> {
        self.provider.compile_outcome_proposal(evidence)
    }

    pub fn record_evidence(
        &self,
        evidence: &SpendEvidence,
    ) -> Result<EvidenceReceipt, RampSpendOutcomeError> {
        self.provider.record_evidence_receipt(evidence)
    }

    pub fn verify_evidence(
        &self,
        receipt: &EvidenceReceipt,
        evidence: &SpendEvidence,
    ) -> Result<EvidenceVerification, RampSpendOutcomeError> {
        self.provider.verify_evidence(receipt, evidence)
    }

    pub fn revoke_registration(&self) -> Result<crate::RevocationReceipt, RampSpendOutcomeError> {
        self.provider.revoke()
    }
}
