//! Standalone Layer-1 governed BigCommerce order-result boundary.
//!
//! The crate contains only typed, bounded GET list/get order evidence and a
//! Mission-scoped proposal/record/read-back seam. It does not resolve native
//! credentials, open HTTP connections, expose customer/payment material, or
//! perform order mutations. Fixture, recording, loopback, and `BLOCKED_ENV`
//! provenance is always non-connected and non-native.

#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::missing_fields_in_debug,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::result_large_err,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

mod consumer;
mod error;
mod model;
mod provider;
mod service;

pub use consumer::{
    MissionBigCommerceOrderConsumer, MissionBigCommerceOrderResult, ProposalDisposition,
    ReadBackFence, RecordedBigCommerceOrderResult,
};
pub use error::{BigCommerceOrderResultError, BigCommerceTransportError, Result};
pub use model::*;
pub use provider::{
    BigCommerceOrderOperation, BigCommerceOrdersProvider, BigCommerceProvider,
    BigCommerceProviderContract, BigCommerceProviderDefinition, BigCommerceTransport,
    BlockedEnvTransport, Cursor, FixtureTransport, GetOrderRequest, GetOrderResponse,
    ListOrdersRequest, ListOrdersResponse, LoopbackTransport, ProviderProvenance, RecordedRequest,
    RecordingTransport, RequestFence,
};
pub use service::{
    BigCommerceOrderEvidence, BigCommerceOrderEvidenceRequest, BigCommerceOrderRegistration,
    BigCommerceOrderResultProposal, BigCommerceOrderResultService, BigCommerceResultProjection,
    EvidenceDigests, EvidenceState, ProviderErrorEvidence, ProviderFailureClass,
    RegistrationStatus, RegistrationTransitionEvidence, RequestReceipt,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.bigcommerce-order-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-BIGCOMMERCE-ORDER-01-L1/v1";
pub const PLUGIN_ID: &str = "bigcommerce.order.result";
pub const PLUGIN_VERSION: &str = "0.1.0";
pub const SERVICE_ID: &str = "bigcommerce.order.result.read";
pub const PROVIDER_ID: &str = "bigcommerce.order.result.recording";
pub const CONSUMER_ID: &str = "mission.bigcommerce-order-result.consumer";
pub const API_REVISION: &str = "bigcommerce-v2-orders-list-get-r1";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.bigcommerce-order-result/v1|layer=1|service=bigcommerce.order.result.read|provider=bigcommerce.order.result.recording|consumer=mission.bigcommerce-order-result.consumer|api=bigcommerce-v2-orders-list-get-r1";
pub const CONTRACT_DIGEST: &str =
    "6744cb0aced7fee61bcbafd1807641c6d6453e1c5e326f05d243685d0d8b0be7";
pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/bigcommerce-order-result/bigcommerce-order-result.v1.json"
);
pub const CONTRACT_PATH: &str =
    "contracts/plugins/bigcommerce-order-result/bigcommerce-order-result.v1.json";

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_PAGE_SIZE: u16 = 50;
pub const MAX_PAGES: u16 = 4;
pub const MAX_ORDERS: usize = 200;
pub const MAX_TRANSACTIONS_PER_ORDER: usize = 32;
pub const MAX_FULFILLMENTS_PER_ORDER: usize = 32;
pub const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const LAYER1_PERMISSIONS: [&str; 3] = [
    "bigcommerce:GET:/stores/{store_hash}/v2/orders",
    "bigcommerce:GET:/stores/{store_hash}/v2/orders/{order_id}",
    "mission.scope",
];

pub const BIGCOMMERCE_ORDER_RESULT_SCHEMA_VERSION: &str = CONTRACT_SCHEMA;
pub const BIGCOMMERCE_ORDER_RESULT_CONTRACT_VERSION: &str = CONTRACT_VERSION;
pub const BIGCOMMERCE_ORDER_RESULT_PLUGIN_ID: &str = PLUGIN_ID;
pub const BIGCOMMERCE_ORDER_RESULT_SERVICE_ID: &str = SERVICE_ID;
pub const BIGCOMMERCE_ORDER_RESULT_PROVIDER_ID: &str = PROVIDER_ID;
pub const MISSION_BIGCOMMERCE_ORDER_CONSUMER_ID: &str = CONSUMER_ID;

/// The contract digest is deliberately over the immutable digest-input
/// sentence, matching the checked-in contract document.
#[must_use]
pub fn contract_digest() -> Digest {
    Digest::from_text(CONTRACT_DIGEST_INPUT)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BigCommerceOrderResultContract {
    document: serde_json::Value,
}

impl BigCommerceOrderResultContract {
    pub fn baseline() -> Result<Self> {
        let document = serde_json::from_str::<serde_json::Value>(CONTRACT_JSON)
            .map_err(|_| BigCommerceOrderResultError::ContractDrift)?;
        let contract = Self { document };
        contract.validate()?;
        Ok(contract)
    }

    #[must_use]
    pub fn document(&self) -> &serde_json::Value {
        &self.document
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        contract_digest()
    }

    pub fn validate(&self) -> Result<()> {
        let object = self
            .document
            .as_object()
            .ok_or(BigCommerceOrderResultError::ContractDrift)?;
        for key in [
            "schemaVersion",
            "contractVersion",
            "pluginVersion",
            "pluginId",
            "layer",
            "evidenceLevel",
            "digestInput",
            "contractDigest",
            "service",
            "provider",
            "consumer",
            "credentials",
            "scope",
            "registration",
            "pagination",
            "projection",
            "receipts",
            "provenance",
            "authorityBoundary",
            "forbiddenEffects",
            "layer2Gaps",
        ] {
            if !object.contains_key(key) {
                return Err(BigCommerceOrderResultError::ContractDrift);
            }
        }
        if self.document["schemaVersion"] != CONTRACT_SCHEMA
            || self.document["contractVersion"] != CONTRACT_VERSION
            || self.document["pluginVersion"] != PLUGIN_VERSION
            || self.document["pluginId"] != PLUGIN_ID
            || self.document["layer"] != "Layer-1"
            || self.document["evidenceLevel"] != EVIDENCE_LEVEL
            || self.document["digestInput"] != CONTRACT_DIGEST_INPUT
            || self.document["contractDigest"] != CONTRACT_DIGEST
            || self.document["service"]["id"] != SERVICE_ID
            || self.document["service"]["implementation"] != "BigCommerceOrderResultService"
            || self.document["provider"]["id"] != PROVIDER_ID
            || self.document["provider"]["implementation"] != "BigCommerceProvider"
            || self.document["consumer"]["id"] != CONSUMER_ID
            || self.document["consumer"]["implementation"] != "MissionBigCommerceOrderConsumer"
            || self.document["service"]["readOnly"] != true
            || self.document["service"]["externalWrites"] != false
            || self.document["provider"]["connectedEvidence"] != false
            || self.document["provider"]["nativeEvidence"] != false
            || self.document["consumer"]["adoptsOutcome"] != false
            || self.document["consumer"]["adoptsWorkProduct"] != false
            || self.document["authorityBoundary"]["connected"] != false
            || self.document["authorityBoundary"]["native"] != false
            || self.document["authorityBoundary"]["financialAdvice"] != false
        {
            return Err(BigCommerceOrderResultError::ContractDrift);
        }
        let operations = self.document["service"]["operations"]
            .as_array()
            .ok_or(BigCommerceOrderResultError::ContractDrift)?;
        if operations.len() != 2
            || operations
                .iter()
                .any(|value| !value.as_str().is_some_and(|text| text.starts_with("GET ")))
        {
            return Err(BigCommerceOrderResultError::ContractDrift);
        }
        if self.document["credentials"]["rawCredentialMaterial"] != false
            || self.document["scope"]["rawAddresses"] != false
            || self.document["scope"]["rawPaymentInstruments"] != false
            || self.document["scope"]["rawCustomerPii"] != false
        {
            return Err(BigCommerceOrderResultError::ContractDrift);
        }
        Ok(())
    }
}

/// Layer 1 has no native, connected, durable, or financial authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    #[must_use]
    pub const fn connected() -> bool {
        false
    }

    #[must_use]
    pub const fn native() -> bool {
        false
    }

    #[must_use]
    pub const fn first_party() -> bool {
        false
    }

    #[must_use]
    pub const fn provider_receipt() -> bool {
        false
    }

    #[must_use]
    pub const fn outcome_authority() -> bool {
        false
    }

    #[must_use]
    pub const fn work_product_authority() -> bool {
        false
    }

    #[must_use]
    pub const fn financial_advice() -> bool {
        false
    }
}

pub type BigCommerceScope = BigCommerceOrderScope;
pub type BigCommerceOrderResult = BigCommerceOrderResultProposal;
pub type BigCommerceOrderResultRegistration = BigCommerceOrderRegistration;
pub type BigCommerceRegistration = BigCommerceOrderRegistration;
pub type BigCommerceOrderProvider<T> = BigCommerceOrdersProvider<T>;
pub type BigCommerceService<P> = BigCommerceOrderResultService<P>;
pub type BigCommerceOrder = BigCommerceOrderSnapshot;
pub type OrderSnapshot = BigCommerceOrderSnapshot;
pub type OrderEvidence = BigCommerceOrderSnapshot;
pub type BigCommerceTransaction = TransactionEvidence;
pub type BigCommerceFulfillment = FulfillmentEvidence;
pub type CustomerFingerprintDigest = CustomerFingerprint;
pub type SecretReference = BigCommerceSecretReference;
pub type AuthKind = BigCommerceAuthKind;
pub type Store = StoreId;
pub type Order = OrderId;
pub type Mission = MissionScope;
pub type Project = ProjectScope;
pub type WorkProduct = WorkProductScope;

#[cfg(test)]
mod contract_tests {
    use serde_json::Value;

    use super::{
        API_REVISION, BigCommerceOrderResultContract, CONSUMER_ID, CONTRACT_DIGEST_INPUT,
        CONTRACT_JSON, CONTRACT_SCHEMA, CONTRACT_VERSION, EVIDENCE_LEVEL, Layer1Authority,
        PLUGIN_ID, PLUGIN_VERSION, PROVIDER_ID, SERVICE_ID, contract_digest,
    };

    #[test]
    fn checked_contract_is_layer_one_and_non_native() {
        BigCommerceOrderResultContract::baseline().expect("checked contract baseline");
        let document: Value = serde_json::from_str(CONTRACT_JSON).expect("contract JSON");
        assert_eq!(document["schemaVersion"], CONTRACT_SCHEMA);
        assert_eq!(document["contractVersion"], CONTRACT_VERSION);
        assert_eq!(document["pluginVersion"], PLUGIN_VERSION);
        assert_eq!(document["pluginId"], PLUGIN_ID);
        assert_eq!(document["layer"], "Layer-1");
        assert_eq!(document["evidenceLevel"], EVIDENCE_LEVEL);
        assert_eq!(document["digestInput"], CONTRACT_DIGEST_INPUT);
        assert_eq!(document["contractDigest"], contract_digest().as_str());
        assert_eq!(document["service"]["id"], SERVICE_ID);
        assert_eq!(document["provider"]["id"], PROVIDER_ID);
        assert_eq!(document["provider"]["apiRevision"], API_REVISION);
        assert_eq!(document["consumer"]["id"], CONSUMER_ID);
        assert_eq!(document["service"]["readOnly"], true);
        assert_eq!(document["service"]["externalWrites"], false);
        assert_eq!(document["credentials"]["rawCredentialMaterial"], false);
        assert_eq!(document["scope"]["rawAddresses"], false);
        assert_eq!(document["scope"]["rawPaymentInstruments"], false);
        assert_eq!(document["scope"]["rawCustomerPii"], false);
        assert_eq!(document["authorityBoundary"]["connected"], false);
        assert_eq!(document["authorityBoundary"]["native"], false);
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native());
        assert!(!Layer1Authority::financial_advice());
    }
}

#[cfg(test)]
mod adversarial_tests;
