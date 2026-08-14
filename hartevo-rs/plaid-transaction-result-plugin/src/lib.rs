//! Standalone Layer-1 Plaid Transactions `/transactions/sync` result plugin.
//!
//! The crate is intentionally local-first and non-native. It binds one
//! environment, opaque Item and account scope, Products permission, cursor,
//! bounded update window, transaction revision, Project/Mission/Work Product,
//! and an opaque host secret reference into a reversible registration. Fixture,
//! recording, loopback, and `BLOCKED_ENV` frames become redacted digest-fenced
//! evidence. Link/public-token creation, refresh, payments, account mutation,
//! raw financial data, financial advice, native HTTPS, durable receipts,
//! independent read-back, and kernel authority remain outside Layer 1.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

use serde::Serialize;
use sha2::{Digest as ShaDigest, Sha256};

pub mod mission;
pub mod model;
pub mod provider;
pub mod service;

pub use mission::{MissionPlaidTransactionConsumer, MissionPlaidTransactionProposal};
pub use model::*;
pub use provider::{
    BlockedEnvPlaidTransport, BlockedEnvSecretResolver, FixturePlaidTransport,
    FixtureSecretResolver, LoopbackPlaidTransport, PlaidHttpResponse, PlaidProviderDescription,
    PlaidSecretResolver, PlaidTransactionsProvider, PlaidTransport, PlaidTransportError,
    PlaidTransportRequest, ProviderSyncRead, RecordingPlaidTransport, ResolvedSecret,
    TransportMode, TransportRequestRecord,
};
pub use service::{PlaidTransactionResultService, PlaidTransactionResultServiceDefinition};

pub const PLAID_TRANSACTION_RESULT_SCHEMA_VERSION: &str =
    "hartevo.plaid-transaction-result.contract/v1";
pub const PLAID_TRANSACTION_RESULT_CONTRACT_VERSION: &str = "plaid-transaction-result/v1";
pub const PLAID_TRANSACTION_RESULT_PLUGIN_VERSION: &str = "0.1.0";
pub const PLAID_TRANSACTION_RESULT_SERVICE_ID: &str = "hartevo.plaid.transaction.result";
pub const PLAID_TRANSACTION_RESULT_PROVIDER_ID: &str = "plaid.transactions";
pub const PLAID_TRANSACTION_RESULT_CONSUMER_ID: &str = "mission.plaid.transaction.result";
pub const PLAID_TRANSACTION_RESULT_API_VERSION: &str = "2020-09-14";
pub const PLAID_TRANSACTION_RESULT_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/plaid-transaction-result/plaid-transaction-result.v1.json"
);

pub(crate) fn digest_bytes(bytes: &[u8]) -> Digest {
    Digest::from_hex(Sha256::digest(bytes))
}

pub(crate) fn digest_serializable<T: Serialize>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("contract values are serializable");
    digest_bytes(&bytes)
}

pub(crate) fn hex_encode(bytes: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = bytes.as_ref();
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod contract_document_tests {
    use serde_json::Value;

    use super::{
        PLAID_TRANSACTION_RESULT_CONTRACT_JSON, PLAID_TRANSACTION_RESULT_CONTRACT_VERSION,
        PLAID_TRANSACTION_RESULT_PLUGIN_VERSION, PLAID_TRANSACTION_RESULT_SCHEMA_VERSION,
    };

    #[test]
    fn checked_contract_keeps_plaid_transactions_layer_one_honest() {
        let contract: Value =
            serde_json::from_str(PLAID_TRANSACTION_RESULT_CONTRACT_JSON).expect("contract JSON");
        assert_eq!(
            contract["schemaVersion"],
            PLAID_TRANSACTION_RESULT_SCHEMA_VERSION
        );
        assert_eq!(
            contract["contractVersion"],
            PLAID_TRANSACTION_RESULT_CONTRACT_VERSION
        );
        assert_eq!(
            contract["pluginVersion"],
            PLAID_TRANSACTION_RESULT_PLUGIN_VERSION
        );
        assert_eq!(contract["layer"], "Layer-1");
        assert_eq!(contract["api"], "/transactions/sync");
        assert_eq!(contract["method"], "POST");
        assert_eq!(contract["authority"]["connected"], false);
        assert_eq!(contract["authority"]["native"], false);
        assert_eq!(contract["authority"]["payments"], false);
        assert_eq!(contract["authority"]["financialAdvice"], false);
        assert_eq!(contract["authority"]["kernelOutcomeAdoption"], false);
        assert_eq!(contract["sync"]["boundedCountMax"], 500);
        assert_eq!(
            contract["sync"]["paginationMutation"],
            "restart_from_first_page_cursor"
        );
        assert_eq!(contract["evidenceModes"].as_array().map(Vec::len), Some(4));
    }
}
