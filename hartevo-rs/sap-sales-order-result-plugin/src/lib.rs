//! Standalone Layer-1 governed SAP S/4HANA sales-order result plugin.
//!
//! The crate stops at a bounded OData read seam, a redacted recording, and a
//! non-mutating Mission proposal. It never resolves credentials, performs a
//! native HTTPS request, changes an ERP document, mints a durable native
//! receipt, independently reads back a write, or adopts a kernel Outcome.

#![allow(
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]

pub const SAP_SALES_ORDER_RESULT_SCHEMA_VERSION: &str =
    "hartevo.sap-sales-order-result.contract/v1";
pub const SAP_SALES_ORDER_RESULT_CONTRACT_VERSION: &str = "sap-sales-order-result/v1";
pub const SAP_SALES_ORDER_RESULT_PLUGIN_VERSION: &str = "0.1.0";
pub const SAP_SALES_ORDER_RESULT_SERVICE_ID: &str = "sap.s4hana.sales-order.result";
pub const SAP_SALES_ORDER_RESULT_PROVIDER_ID: &str = "sap.s4hana.sales-order-a2x-odata-v2";
pub const MISSION_SAP_SALES_ORDER_CONSUMER_ID: &str = "mission.sap.sales-order.result";
pub const SAP_SALES_ORDER_RESULT_IMPLEMENTATION: &str = "SapS4HanaProvider/layer1/v1";
pub const SAP_SALES_ORDER_RESULT_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const SAP_SALES_ORDER_RESULT_API_BASIS: &str = "https://help.sap.com/docs/SAP_S4HANA_CLOUD/03c04db2a7434731b7fe21dca77440da/641bd0dc16bf406684ca2c614322c15e.html";
pub const SAP_SALES_ORDER_RESULT_READ_REQUESTS_API_BASIS: &str = "https://help.sap.com/docs/SAP_S4HANA_CLOUD/03c04db2a7434731b7fe21dca77440da/275f93c02de54f3e8ee7fa2eeddd7282.html";
pub const SAP_SALES_ORDER_RESULT_CONTRACT_PATH: &str =
    "contracts/plugins/sap-sales-order-result/sap-sales-order-result.v1.json";
pub const SAP_SALES_ORDER_RESULT_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/sap-sales-order-result/sap-sales-order-result.v1.json"
);

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    MissionSapSalesOrderConsumer, MissionSapSalesOrderConsumerDefinition,
    MissionSapSalesOrderConsumerError, MissionSapSalesOrderResult, MissionSapSalesOrderState,
};
pub use model::{
    BlockState, ConsumerId, Digest, FulfillmentState, MissionId, ModelError, MoneySummary,
    OpaqueDocumentId, OpaqueEtag, OrderLifecycleState, PermissionLease, ProjectId,
    ProviderErrorEvidence, ProviderId, RedactionSummary, RegistrationState, Revision,
    RevisionBinding, RevisionFence, SalesOrderDocumentFlowProjection, SalesOrderHeaderProjection,
    SalesOrderId, SalesOrderItemProjection, SapEntitySet, SapODataPage, SapODataVersion,
    SapObservationState, SapPermission, SapProviderErrorKind, SapQueryBounds, SapRedactionPolicy,
    SapRegistration, SapSalesOrderEvidence, SapSalesOrderObservation, SapSalesOrderScope,
    SapTransportProvenance, SecretKind, SecretReference, ServiceId, SystemId, TenantId,
    WorkProductId, allowlisted_fields,
};
pub use provider::{
    BlockedEnvSapODataTransport, BlockedEnvTransport, FixtureSapODataTransport, FixtureTransport,
    LoopbackSapODataTransport, LoopbackTransport, ProviderDefinitionError,
    RecordingSapODataTransport, RecordingTransport, SapODataFilter, SapODataRequest,
    SapODataResponse, SapODataTransport, SapProviderDefinition, SapProviderError,
    SapS4HanaProvider, SapS4HanaProviderDefinition, SapTransportError,
};
pub use service::{
    SapSalesOrderAdoptionProposal, SapSalesOrderOperation, SapSalesOrderReadProposal,
    SapSalesOrderRecording, SapSalesOrderResultService,
    SapSalesOrderResultService as SapSalesOrderService, SapSalesOrderRun,
    SapSalesOrderServiceDefinition, SapSalesOrderServiceError,
};

pub type SapSalesOrderResultServiceError = SapSalesOrderServiceError;

pub type MissionSapSalesOrderResultConsumer = MissionSapSalesOrderConsumer;
pub type SapSalesOrderProvider<T = BlockedEnvSapODataTransport> = SapS4HanaProvider<T>;
pub type SapSecretReference = SecretReference;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    pub const fn connected() -> bool {
        false
    }

    pub const fn native_provider() -> bool {
        false
    }

    pub const fn native() -> bool {
        false
    }

    pub const fn first_party() -> bool {
        false
    }

    pub const fn durable_native_receipt() -> bool {
        false
    }

    pub const fn independent_read_back() -> bool {
        false
    }

    pub const fn adopted_outcome() -> bool {
        false
    }

    pub const fn truth_authority() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_document_tests {
    use serde_json::Value;

    use super::{
        Layer1Authority, MISSION_SAP_SALES_ORDER_CONSUMER_ID, SAP_SALES_ORDER_RESULT_BLOCKED_ENV,
        SAP_SALES_ORDER_RESULT_CONTRACT_JSON, SAP_SALES_ORDER_RESULT_CONTRACT_VERSION,
        SAP_SALES_ORDER_RESULT_PROVIDER_ID, SAP_SALES_ORDER_RESULT_SCHEMA_VERSION,
        SAP_SALES_ORDER_RESULT_SERVICE_ID,
    };

    #[test]
    fn contract_document_keeps_layer_one_honest() {
        let document: Value =
            serde_json::from_str(SAP_SALES_ORDER_RESULT_CONTRACT_JSON).expect("contract JSON");
        assert_eq!(
            document["schemaVersion"],
            SAP_SALES_ORDER_RESULT_SCHEMA_VERSION
        );
        assert_eq!(
            document["contractVersion"],
            SAP_SALES_ORDER_RESULT_CONTRACT_VERSION
        );
        assert_eq!(document["layer"], "Layer-1");
        assert_eq!(document["serviceId"], SAP_SALES_ORDER_RESULT_SERVICE_ID);
        assert_eq!(document["providerId"], SAP_SALES_ORDER_RESULT_PROVIDER_ID);
        assert_eq!(document["consumerId"], MISSION_SAP_SALES_ORDER_CONSUMER_ID);
        assert_eq!(document["readAllowlist"]["odataVersion"], "V2");
        for claim in [
            "connected",
            "native",
            "firstParty",
            "externalWrites",
            "durableNativeReceipt",
            "independentReadBack",
            "kernelOutcomeAdoption",
            "truthAuthority",
        ] {
            assert_eq!(document["authority"][claim], false, "{claim}");
        }
        assert_eq!(SAP_SALES_ORDER_RESULT_BLOCKED_ENV, "BLOCKED_ENV");
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::durable_native_receipt());
        assert!(!Layer1Authority::independent_read_back());
        assert!(!Layer1Authority::adopted_outcome());
        assert!(!Layer1Authority::truth_authority());
    }
}
