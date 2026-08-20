//! Typed Layer-1 DocuSign signature authority for Hartevo.
//!
//! This crate stops at envelope proposals, deterministic receipt/status
//! projection, and revision-fenced signed-result adoption proposals. It does
//! not create or send an envelope, begin a signing ceremony, perform document
//! readback, process a live Connect webhook, or claim Connected/native
//! evidence. The HTTPS/OAuth 2.0 transport is an explicit Layer-2 seam and
//! receives only the Connector SDK's opaque SecretReference.

mod consumer;
mod contract;
mod digest;
mod model;
mod provider;
mod registration;
mod service;

pub use consumer::{ConsumerError, MissionSignedResultConsumer};
pub use contract::{
    ContractError, DOCUSIGN_SIGNATURE_CONTRACT_JSON, DOCUSIGN_SIGNATURE_CONTRACT_VERSION,
    DOCUSIGN_SIGNATURE_SCHEMA_VERSION, DocuSignSignatureContract, contract_digest,
};
pub use digest::{Digest, DigestError};
pub use hartevo_domain_kernel::{MissionId, ProjectId, TenantId};
pub use model::{
    BaseUri, CompletionBlockReason, CompletionEvidence, DOCUSIGN_NATIVE_OPT_IN_ENV,
    DOCUSIGN_PROVIDER_ID, DocuSignAccountId, DocuSignReceipt, DocuSignScope, DocumentContentType,
    DocumentId, DocumentReference, EnvelopeContent, EnvelopeId, EnvelopeProposal,
    EnvelopeProposalRequest, EnvelopeStatus, EnvelopeStatusProjection, ModelError, NativeOperation,
    NonConnectedEvidence, ProviderProvenance, ProviderVersion, RecipientId, RecipientRole,
    RecipientSpec, RecipientStatus, RecipientStatusProjection, RecordedEnvelopeObservation,
    RedactionState, RedactionSummary, RevisionFence, RoutingOrder, RoutingPlan, RoutingStep,
    SignedResultAdoptionProposal, SignedResultSource, TemplateId, TemplateReference,
};
pub use provider::{
    BlockedEnvDocuSignTransport, DocuSignHttpRequest, DocuSignHttpResponse,
    DocuSignSignatureProvider, DocuSignTransport, DocuSignTransportError, FixtureDocuSignTransport,
    HttpMethod, LoopbackDocuSignTransport, NativeOptInDocuSignTransport, PollPlan, PollPlanError,
    ProviderAvailability, ProviderError, SignatureProvider,
};
pub use registration::{
    DOCUSIGN_PLUGIN_ID, DOCUSIGN_PLUGIN_VERSION, DOCUSIGN_PROVIDER_DEFINITION_ID,
    DocuSignPluginRegistration, DocuSignRegistrationReceipt, MISSION_SIGNED_RESULT_CONSUMER_ID,
    RegistrationError,
};
pub use service::{DocuSignSignatureService, ServiceError};

pub const DOCUSIGN_SIGNATURE_SERVICE_ID: &str = "docusign.signature.service";
pub const LAYER_1_EVIDENCE_LEVEL: &str = "E1";

#[cfg(test)]
mod contract_tests {
    use super::{
        DOCUSIGN_SIGNATURE_CONTRACT_VERSION, DOCUSIGN_SIGNATURE_SCHEMA_VERSION,
        DocuSignSignatureContract, LAYER_1_EVIDENCE_LEVEL, contract_digest,
    };

    #[test]
    fn checked_contract_is_layer1_only_and_digestable() {
        let contract = DocuSignSignatureContract::baseline().expect("contract");
        assert_eq!(contract.schema_version(), DOCUSIGN_SIGNATURE_SCHEMA_VERSION);
        assert_eq!(
            contract.contract_version(),
            DOCUSIGN_SIGNATURE_CONTRACT_VERSION
        );
        assert_eq!(contract.evidence_level(), LAYER_1_EVIDENCE_LEVEL);
        assert_eq!(contract.digest(), contract_digest());
    }
}
