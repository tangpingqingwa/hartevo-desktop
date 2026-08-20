//! Standalone Layer-1 governed Brex spend-control result boundary.
//!
//! This crate is deliberately below Hartevo Truth, Effect, Receipt,
//! Verification, Outcome, and durable Work Product authority. It exposes only
//! bounded, redacted read/proposal/record/verify seams and reversible
//! scope-bound registration. No transport in this crate is Connected, native,
//! first-party, or capable of mutating Brex data.

#![forbid(unsafe_code)]
#![allow(
    clippy::assigning_clones,
    clippy::collapsible_if,
    clippy::format_push_string,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::missing_fields_in_debug,
    clippy::needless_pass_by_value,
    clippy::redundant_closure_for_method_calls,
    clippy::result_large_err,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]

mod consumer;
mod error;
mod model;
mod provider;
mod service;

pub use consumer::{
    MissionBrexSpendConsumer, MissionBrexSpendConsumerError, MissionBrexSpendResult,
    MissionBrexSpendResultState, RecordedBrexSpendResult,
};
pub use error::{BrexSpendError, BrexSpendTransportError, Result};
pub use model::*;
pub use provider::*;
pub use service::*;

pub const CONTRACT_SCHEMA: &str = "hartevo.brex-spend-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-BREX-01-L1/v1";
pub const PLUGIN_ID: &str = "brex.spend-result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "brex.spend.result";
pub const PROVIDER_ID: &str = "brex.spend.read";
pub const PROVIDER_API_REVISION: &str = "brex-spend-read-v1";
pub const PROVIDER_VERSION: &str = "brex-spend-provider/v1";
pub const CONSUMER_ID: &str = "mission.brex-spend-result.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.brex-spend-result/v1|layer=1|service=brex.spend.result|provider=brex.spend.read|consumer=mission.brex-spend-result.consumer";
pub const CONTRACT_DIGEST: &str =
    "6ece8c89d4619a65f7b27b886b6ca3aecd570dc81018deb7a4579d07cda7d39a";
pub const CONTRACT_PATH: &str = "contracts/plugins/brex-spend-result/brex-spend-result.v1.json";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/brex-spend-result/brex-spend-result.v1.json");
pub const MAX_PAGE_SIZE: usize = 50;
pub const MAX_PAGES: usize = 4;
pub const MAX_ITEMS: usize = 128;
pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_RETRY_AFTER_SECONDS: u32 = 3_600;

// Explicitly named aliases keep the contract vocabulary discoverable to host
// code while the shorter sibling-plugin constants remain available.
pub const BREX_SPEND_RESULT_SCHEMA_VERSION: &str = CONTRACT_SCHEMA;
pub const BREX_SPEND_RESULT_CONTRACT_VERSION: &str = CONTRACT_VERSION;
pub const BREX_SPEND_RESULT_PLUGIN_ID: &str = PLUGIN_ID;
pub const BREX_SPEND_RESULT_PLUGIN_VERSION: &str = PLUGIN_VERSION;
pub const BREX_SPEND_RESULT_SERVICE_ID: &str = SERVICE_ID;
pub const BREX_SPEND_RESULT_PROVIDER_ID: &str = PROVIDER_ID;
pub const BREX_SPEND_RESULT_CONSUMER_ID: &str = CONSUMER_ID;
pub const BREX_SPEND_RESULT_CONTRACT_DIGEST: &str = CONTRACT_DIGEST;
pub const BREX_SPEND_RESULT_CONTRACT_JSON: &str = CONTRACT_JSON;

/// Layer 1's explicit authority boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    #[must_use]
    pub const fn connected() -> bool {
        false
    }

    #[must_use]
    pub const fn native_provider() -> bool {
        false
    }

    #[must_use]
    pub const fn first_party() -> bool {
        false
    }

    #[must_use]
    pub const fn durable_receipt() -> bool {
        false
    }

    #[must_use]
    pub const fn effective_authorization() -> bool {
        false
    }

    #[must_use]
    pub const fn financial_advice() -> bool {
        false
    }

    #[must_use]
    pub const fn external_writes() -> bool {
        false
    }
}

#[must_use]
pub fn contract_digest() -> Digest {
    Digest::from_text(CONTRACT_DIGEST_INPUT)
}

#[must_use]
pub(crate) fn plugin_version_digest() -> Digest {
    Digest::from_text(PLUGIN_VERSION)
}

#[cfg(test)]
mod contract_document_tests {
    use serde_json::Value;

    use super::{
        BLOCKED_ENV, CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_DIGEST_INPUT, CONTRACT_JSON,
        CONTRACT_SCHEMA, CONTRACT_VERSION, EVIDENCE_LEVEL, Layer1Authority, PROVIDER_API_REVISION,
        PROVIDER_ID, SERVICE_ID, contract_digest,
    };

    #[test]
    fn contract_is_machine_readable_and_layer_one_honest() {
        let document: Value = serde_json::from_str(CONTRACT_JSON).expect("Brex contract JSON");
        assert_eq!(document["schemaVersion"], CONTRACT_SCHEMA);
        assert_eq!(document["contractVersion"], CONTRACT_VERSION);
        assert_eq!(document["contractDigestInput"], CONTRACT_DIGEST_INPUT);
        assert_eq!(document["contractDigest"], CONTRACT_DIGEST);
        assert_eq!(document["layer"], 1);
        assert_eq!(document["evidenceLevel"], EVIDENCE_LEVEL);
        assert_eq!(document["service"]["id"], SERVICE_ID);
        assert_eq!(document["provider"]["id"], PROVIDER_ID);
        assert_eq!(document["provider"]["apiRevision"], PROVIDER_API_REVISION);
        assert_eq!(document["consumer"]["id"], CONSUMER_ID);
        assert_eq!(document["provider"]["connectedEvidence"], false);
        assert_eq!(document["provider"]["nativeEvidence"], false);
        assert_eq!(document["provider"]["firstPartyEvidence"], false);
        assert_eq!(document["service"]["externalWrites"], false);
        assert_eq!(document["service"]["kernelAuthority"], false);
        assert_eq!(document["consumer"]["adoptsOutcome"], false);
        assert_eq!(document["consumer"]["adoptsWorkProduct"], false);
        assert_eq!(
            document["provenance"]["blockedEnv"],
            "non_native_non_connected_non_first_party"
        );
        assert_eq!(BLOCKED_ENV, "BLOCKED_ENV");
        assert_eq!(contract_digest().as_str(), CONTRACT_DIGEST);
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::durable_receipt());
        assert!(!Layer1Authority::effective_authorization());
        assert!(!Layer1Authority::financial_advice());
        assert!(!Layer1Authority::external_writes());
    }
}
