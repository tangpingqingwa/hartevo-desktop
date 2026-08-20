use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::model::{
    AdyenPaymentEvidence, AdyenPaymentProjection, AdyenPaymentReceipt, AdyenPaymentRegistration,
    AdyenPaymentResultProposal, AdyenPaymentScope, AdyenReadBackVerification, Digest,
    PluginVersion,
};
use crate::provider::{AdyenCredentialResolver, AdyenPaymentsProvider};
use crate::transport::AdyenPaymentTransport;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdyenServiceOperation {
    RetrievePayment,
    ReadPaymentStatus,
    CompilePaymentResultProposal,
    RecordPaymentReceipt,
    ReadBackAndVerify,
    VerifyPaymentResult,
    Registration,
    Revocation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct AdyenServiceDefinition {
    pub schema_version: String,
    pub contract_version: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub plugin_id: String,
    pub plugin_version: PluginVersion,
    pub operations: Vec<AdyenServiceOperation>,
    pub read_only: bool,
    pub proposal_only: bool,
    pub recording_only: bool,
    pub external_writes: bool,
    pub kernel_authority: bool,
    pub financial_advice: bool,
}

impl AdyenServiceDefinition {
    pub fn layer1() -> Self {
        Self {
            schema_version: crate::SCHEMA_VERSION.to_owned(),
            contract_version: crate::CONTRACT_VERSION.to_owned(),
            service_id: crate::SERVICE_ID.to_owned(),
            provider_id: crate::PROVIDER_ID.to_owned(),
            consumer_id: crate::CONSUMER_ID.to_owned(),
            plugin_id: crate::PLUGIN_ID.to_owned(),
            plugin_version: crate::PLUGIN_VERSION,
            operations: vec![
                AdyenServiceOperation::RetrievePayment,
                AdyenServiceOperation::ReadPaymentStatus,
                AdyenServiceOperation::CompilePaymentResultProposal,
                AdyenServiceOperation::RecordPaymentReceipt,
                AdyenServiceOperation::ReadBackAndVerify,
                AdyenServiceOperation::VerifyPaymentResult,
                AdyenServiceOperation::Registration,
                AdyenServiceOperation::Revocation,
            ],
            read_only: true,
            proposal_only: true,
            recording_only: true,
            external_writes: false,
            kernel_authority: false,
            financial_advice: false,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != crate::SCHEMA_VERSION
            || self.contract_version != crate::CONTRACT_VERSION
            || self.service_id != crate::SERVICE_ID
            || self.provider_id != crate::PROVIDER_ID
            || self.consumer_id != crate::CONSUMER_ID
            || self.plugin_id != crate::PLUGIN_ID
            || self.plugin_version != crate::PLUGIN_VERSION
            || self.operations.len() != 8
            || !self.read_only
            || !self.proposal_only
            || !self.recording_only
            || self.external_writes
            || self.kernel_authority
            || self.financial_advice
        {
            return Err(crate::AdyenPaymentResultError::MutationForbidden {
                operation: "invalid service definition",
            });
        }
        Ok(())
    }

    pub fn digest(&self) -> Digest {
        crate::Digest::from_text(
            serde_json::to_vec(self).expect("Adyen service definition is serializable"),
        )
    }
}

/// Mission-facing service containing only the typed read/proposal/record
/// boundary. It has no external effect capability.
#[derive(Debug)]
pub struct AdyenPaymentResultService<T, R>
where
    T: AdyenPaymentTransport,
    R: AdyenCredentialResolver,
{
    provider: AdyenPaymentsProvider<T, R>,
    definition: AdyenServiceDefinition,
}

impl<T, R> AdyenPaymentResultService<T, R>
where
    T: AdyenPaymentTransport,
    R: AdyenCredentialResolver,
{
    pub fn new(provider: AdyenPaymentsProvider<T, R>) -> Result<Self> {
        let definition = AdyenServiceDefinition::layer1();
        definition.validate()?;
        Ok(Self {
            provider,
            definition,
        })
    }

    pub fn definition(&self) -> &AdyenServiceDefinition {
        &self.definition
    }

    pub fn provider(&self) -> &AdyenPaymentsProvider<T, R> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut AdyenPaymentsProvider<T, R> {
        &mut self.provider
    }

    pub fn registration(&self) -> &AdyenPaymentRegistration {
        self.provider.registration()
    }

    pub fn scope(&self) -> &AdyenPaymentScope {
        self.provider.scope()
    }

    pub fn retrieve_payment(&mut self) -> Result<AdyenPaymentProjection> {
        self.provider.retrieve_payment()
    }

    pub fn read_payment_status(&mut self) -> Result<AdyenPaymentProjection> {
        self.provider.read_payment_status()
    }

    pub fn read_evidence(&mut self) -> Result<AdyenPaymentEvidence> {
        self.provider.read_evidence()
    }

    pub fn record_payment_receipt(
        &self,
        evidence: &AdyenPaymentEvidence,
        recorded_at_ms: u64,
    ) -> Result<AdyenPaymentReceipt> {
        self.provider
            .record_payment_receipt(evidence, recorded_at_ms)
    }

    pub fn compile_payment_result_proposal(
        &self,
        evidence: &AdyenPaymentEvidence,
        receipt: &AdyenPaymentReceipt,
    ) -> Result<AdyenPaymentResultProposal> {
        self.provider
            .compile_payment_result_proposal(evidence, receipt)
    }

    pub fn verify_payment_result(
        &self,
        proposal: &AdyenPaymentResultProposal,
        evidence: &AdyenPaymentEvidence,
        receipt: &AdyenPaymentReceipt,
    ) -> Result<AdyenPaymentResultProposal> {
        self.provider
            .verify_payment_result(proposal, evidence, receipt)
    }

    pub fn read_back_and_verify(
        &mut self,
        evidence: &AdyenPaymentEvidence,
    ) -> Result<AdyenReadBackVerification> {
        self.provider.read_back_and_verify(evidence)
    }

    pub fn revoke(&mut self, revoked_at_ms: u64) -> Result<crate::RegistrationRevocation> {
        self.provider.revoke(revoked_at_ms)
    }

    pub fn reject_write(&self, operation: &'static str) -> Result<()> {
        self.provider.reject_write(operation)
    }
}

pub type AdyenReadOnlyService<T, R> = AdyenPaymentResultService<T, R>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layer1_definition_is_complete_and_read_only() {
        let definition = AdyenServiceDefinition::layer1();
        definition.validate().expect("valid definition");
        assert_eq!(definition.operations.len(), 8);
        assert!(definition.read_only);
        assert!(definition.proposal_only);
        assert!(definition.recording_only);
        assert!(!definition.external_writes);
        assert!(!definition.kernel_authority);
        assert!(!definition.financial_advice);
    }
}
