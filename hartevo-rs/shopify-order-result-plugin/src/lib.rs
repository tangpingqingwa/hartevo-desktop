//! Layer-1 governed Shopify order-result evidence.
//!
//! This crate is deliberately standalone. It describes one scoped Shopify
//! Admin GraphQL read, records bounded redacted evidence from a fixture or
//! recording, and proposes evidence-only Mission consumption. It never
//! resolves a native credential, reports Connected/native/first-party,
//! mutates Shopify, retains a GraphQL body, issues a durable native receipt,
//! reads back a write, or adopts a Work Product.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

mod consumer;
mod model;
mod provider;
mod service;

pub use consumer::{
    ConsumerError, MissionShopifyOrderConsumer, MissionShopifyOrderResult,
    MissionShopifyOrderResultState,
};
pub use model::*;
pub use provider::{
    BlockedEnvReason, EvidenceDisposition, GraphqlResponse, PageInfo, ProviderFailure,
    ProviderFailureClass, ProviderMode, ProviderProvenance, ResponseMetadata, ShopifyAdminProvider,
    ShopifyAdminProviderDefinition, ShopifyOrderEvidence, ShopifyProviderError,
};
pub use service::{
    AdoptionMode, ShopifyAdoptionProposal, ShopifyCapabilities, ShopifyOrderReadProposal,
    ShopifyOrderResultService, ShopifyServiceError,
};

pub const SHOPIFY_ORDER_RESULT_SCHEMA_VERSION: &str = "hartevo.shopify-order-result-contract/v1";
pub const SHOPIFY_ORDER_RESULT_CONTRACT_VERSION: &str = "shopify-order-result/v1";
pub const SHOPIFY_ORDER_RESULT_PLUGIN_VERSION: &str = "0.1.0";
pub const SHOPIFY_ADMIN_API_VERSION: &str = "2026-07";
pub const SHOPIFY_ORDER_RESULT_SERVICE_ID: &str = "shopify.order-result";
pub const SHOPIFY_ADMIN_PROVIDER_ID: &str = "shopify.admin";
pub const MISSION_SHOPIFY_ORDER_RESULT_CONSUMER_ID: &str = "mission.shopify-order-result";
pub const SHOPIFY_ORDER_RESULT_SERVICE_NAME: &str = "ShopifyOrderResultService";
pub const SHOPIFY_ADMIN_PROVIDER_NAME: &str = "ShopifyAdminProvider";
pub const MISSION_SHOPIFY_ORDER_CONSUMER_NAME: &str = "MissionShopifyOrderConsumer";
pub const SHOPIFY_ORDER_RESULT_BLOCKED_ENV: &str = "BLOCKED_ENV";

pub const SHOPIFY_ORDER_RESULT_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/shopify-order-result/shopify-order-result.v1.json");

/// The only GraphQL selection that Layer 1 can propose.
///
/// It intentionally excludes customer, address, line-item, payment-instrument,
/// gateway, note, and all mutation selections. The provider parses only these
/// fields and drops the input bytes before returning.
pub const SHOPIFY_ORDER_RESULT_QUERY_DOCUMENT: &str = r"
query HartevoShopifyOrderResult($orderId: ID!, $pageSize: Int!, $after: String) {
  order(id: $orderId) {
    id
    createdAt
    updatedAt
    currencyCode
    displayFinancialStatus
    displayFulfillmentStatus
    currentTotalPriceSet { shopMoney { amount currencyCode } }
    totalRefundedSet { shopMoney { amount currencyCode } }
    fulfillmentOrders(first: $pageSize, after: $after) {
      nodes { id status requestStatus createdAt updatedAt }
      pageInfo { hasNextPage endCursor }
    }
    fulfillments { id status createdAt updatedAt }
    refunds(first: $pageSize) {
      id
      createdAt
      processedAt
      updatedAt
      totalRefundedSet { shopMoney { amount currencyCode } }
      transactions(first: $pageSize) {
        nodes { id status }
        pageInfo { hasNextPage endCursor }
      }
    }
    transactions(first: $pageSize) {
      id
      kind
      status
      amountSet { shopMoney { amount currencyCode } }
      createdAt
      processedAt
    }
  }
}
";

/// Layer 1's authority is intentionally empty even when evidence is complete.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    pub const fn connected() -> bool {
        false
    }

    pub const fn native() -> bool {
        false
    }

    pub const fn first_party() -> bool {
        false
    }

    pub const fn external_writes() -> bool {
        false
    }

    pub const fn payment_authority() -> bool {
        false
    }

    pub const fn durable_native_receipt() -> bool {
        false
    }

    pub const fn independent_read_back() -> bool {
        false
    }

    pub const fn verified_work_product_adoption() -> bool {
        false
    }
}

/// SHA-256 of the checked-in contract document.
pub fn contract_digest() -> Digest {
    Digest::sha256(SHOPIFY_ORDER_RESULT_CONTRACT_JSON.as_bytes())
}

/// The contract document is parsed and checked in every standalone test.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShopifyOrderResultContract {
    document: serde_json::Value,
}

impl ShopifyOrderResultContract {
    pub fn baseline() -> Result<Self, ShopifyServiceError> {
        let document =
            serde_json::from_str::<serde_json::Value>(SHOPIFY_ORDER_RESULT_CONTRACT_JSON)
                .map_err(|error| ShopifyServiceError::Contract(error.to_string()))?;
        let contract = Self { document };
        contract.validate()?;
        Ok(contract)
    }

    pub fn document(&self) -> &serde_json::Value {
        &self.document
    }

    pub fn digest(&self) -> Digest {
        contract_digest()
    }

    pub fn validate(&self) -> Result<(), ShopifyServiceError> {
        let value = &self.document;
        let exact = [
            ("schemaVersion", SHOPIFY_ORDER_RESULT_SCHEMA_VERSION),
            ("contractVersion", SHOPIFY_ORDER_RESULT_CONTRACT_VERSION),
            ("pluginVersion", SHOPIFY_ORDER_RESULT_PLUGIN_VERSION),
            ("apiVersion", SHOPIFY_ADMIN_API_VERSION),
            ("service.id", SHOPIFY_ORDER_RESULT_SERVICE_ID),
            ("service.implementation", SHOPIFY_ORDER_RESULT_SERVICE_NAME),
            ("provider.id", SHOPIFY_ADMIN_PROVIDER_ID),
            ("provider.implementation", SHOPIFY_ADMIN_PROVIDER_NAME),
            ("consumer.id", MISSION_SHOPIFY_ORDER_RESULT_CONSUMER_ID),
            (
                "consumer.implementation",
                MISSION_SHOPIFY_ORDER_CONSUMER_NAME,
            ),
        ];
        for (path, expected) in exact {
            if path_value(value, path).and_then(serde_json::Value::as_str) != Some(expected) {
                return Err(ShopifyServiceError::Contract(format!(
                    "{path} does not match the Layer-1 baseline"
                )));
            }
        }
        let false_flags = [
            "service.readOnly",
            "service.liveExecution",
            "service.paymentAuthority",
        ];
        for path in false_flags {
            if path == "service.readOnly" {
                if path_value(value, path).and_then(serde_json::Value::as_bool) != Some(true) {
                    return Err(ShopifyServiceError::Contract(format!(
                        "{path} must be true"
                    )));
                }
            } else if path_value(value, path).and_then(serde_json::Value::as_bool) != Some(false) {
                return Err(ShopifyServiceError::Contract(format!(
                    "{path} must be false"
                )));
            }
        }
        let required_false = [
            "provider.native",
            "provider.connected",
            "provider.firstParty",
            "provider.externalWrites",
            "consumer.adoptsOutcome",
            "consumer.adoptsWorkProduct",
            "consumer.truthAuthority",
            "consumer.paymentAuthority",
            "evidence.rawGraphqlBodyRetained",
            "evidence.rawGraphqlErrorsRetained",
            "evidence.customerPiiRetained",
            "evidence.lineItemsRetained",
            "evidence.addressesRetained",
            "evidence.paymentInstrumentRetained",
            "evidence.durableNativeReceipt",
            "authority.connected",
            "authority.native",
            "authority.firstParty",
            "authority.externalWrites",
            "authority.paymentAuthority",
            "authority.truthAuthority",
            "authority.consentAuthority",
            "authority.effectAuthority",
            "authority.receiptAuthority",
            "authority.verificationAuthority",
            "authority.outcomeAuthority",
            "authority.independentReadBack",
            "authority.verifiedWorkProductAdoption",
        ];
        for path in required_false {
            if path_value(value, path).and_then(serde_json::Value::as_bool) != Some(false) {
                return Err(ShopifyServiceError::Contract(format!(
                    "{path} must be false"
                )));
            }
        }
        if path_value(value, "layer").and_then(serde_json::Value::as_str) != Some("Layer-1")
            || path_value(value, "queryPolicy.oneOrderOnly").and_then(serde_json::Value::as_bool)
                != Some(true)
            || path_value(value, "queryPolicy.allowlistedSelectionOnly")
                .and_then(serde_json::Value::as_bool)
                != Some(true)
            || path_value(value, "registration.reversible").and_then(serde_json::Value::as_bool)
                != Some(true)
            || path_value(value, "registration.revocable").and_then(serde_json::Value::as_bool)
                != Some(true)
            || path_value(value, "evidence.bounded").and_then(serde_json::Value::as_bool)
                != Some(true)
        {
            return Err(ShopifyServiceError::Contract(
                "Shopify order-result contract does not match the Layer-1 baseline".to_owned(),
            ));
        }
        let modes = path_value(value, "evidenceModes")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| {
                ShopifyServiceError::Contract("evidenceModes is not an array".to_owned())
            })?
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect::<Vec<_>>();
        if modes != ["fixture", "recording", "loopback", "BLOCKED_ENV"] {
            return Err(ShopifyServiceError::Contract(
                "evidence modes must remain non-native".to_owned(),
            ));
        }
        if SHOPIFY_ORDER_RESULT_QUERY_DOCUMENT
            .to_ascii_lowercase()
            .contains("mutation")
        {
            return Err(ShopifyServiceError::Contract(
                "allowlisted query must not contain a mutation".to_owned(),
            ));
        }
        for forbidden in [
            "customer",
            "shippingaddress",
            "billingaddress",
            "lineitems",
            "paymentinstrument",
            "paymentdetails",
            "gateway",
        ] {
            if SHOPIFY_ORDER_RESULT_QUERY_DOCUMENT
                .to_ascii_lowercase()
                .contains(forbidden)
            {
                return Err(ShopifyServiceError::Contract(format!(
                    "allowlisted query contains forbidden field {forbidden}"
                )));
            }
        }
        Ok(())
    }
}

fn path_value<'a>(value: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    path.split('.')
        .try_fold(value, |current, segment| current.get(segment))
}

#[cfg(test)]
mod contract_document_tests {
    use super::*;

    #[test]
    fn checked_contract_is_layer_one_and_non_native() {
        let contract = ShopifyOrderResultContract::baseline().expect("contract");
        assert_eq!(contract.digest(), contract_digest());
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::external_writes());
        assert!(!Layer1Authority::payment_authority());
        assert!(!Layer1Authority::durable_native_receipt());
        assert!(!Layer1Authority::independent_read_back());
        assert!(!Layer1Authority::verified_work_product_adoption());
    }
}
