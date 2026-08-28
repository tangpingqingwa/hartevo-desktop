//! Layer-1 Paddle subscription and transaction lifecycle result proposal.
//!
//! This crate is intentionally standalone. It models the official Paddle
//! Billing GET surfaces through a typed transport seam, but ships no native
//! credential resolver or HTTPS client. Fixture, recording, loopback, and
//! `BLOCKED_ENV` evidence never claims Connected/native/first-party status and
//! never becomes Hartevo Truth, Effect, Receipt, Verification, or Outcome
//! authority.

#![forbid(unsafe_code)]
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
mod error;
mod model;
mod provider;
mod service;
mod transport;

pub use consumer::{
    MissionPaddleSubscriptionConsumer, MissionPaddleSubscriptionResult, MissionResultState,
};
pub use error::{PaddleBillingProviderError, PaddleSubscriptionResultError, Result};
pub use model::*;
pub use provider::{
    PaddleBillingProvider, PaddleBillingProviderDefinition, PaddleEventListResponse,
    PaddleSubscriptionResponse, PaddleTransactionListResponse, PaddleTransactionResponse,
};
pub use service::{
    PaddleBillingCapabilities, PaddleBillingReadProposal, PaddleBillingResultProposal,
    PaddleBillingServicePolicy, PaddleSubscriptionResultService,
};
pub use transport::{
    BlockedEnvPaddleBillingTransport, FakePaddleBillingTransport, FixturePaddleBillingTransport,
    LoopbackPaddleBillingTransport, PaddleGetRequest, PaddleHttpMethod, PaddleHttpResponse,
    PaddleTransport, PaddleTransportError, RecordingPaddleBillingTransport,
};

pub const SCHEMA_VERSION: &str = "hartevo.paddle-subscription-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-PADDLE-01-L1/v1";
pub const PLUGIN_ID: &str = "hartevo.paddle-subscription-result";
pub const PLUGIN_VERSION: &str = "0.1.0";
pub const PROVIDER_ID: &str = "paddle.billing.read";
pub const PROVIDER_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "PaddleSubscriptionResultService";
pub const CONSUMER_ID: &str = "MissionPaddleSubscriptionConsumer";
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const PADDLE_API_VERSION: &str = "1";
pub const OFFICIAL_PADDLE_HOST: &str = "https://api.paddle.com";
pub const EVENT_RETENTION_SECONDS: u64 = 90 * 24 * 60 * 60;
pub const NATIVE_GAP: &str = "BLOCKED_ENV: native Paddle API-key resolution, bounded live HTTPS reads, durable native receipt, independent readback, and verified Work Product adoption remain Layer-2 gaps";
pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/paddle-subscription-result/paddle-subscription-result.v1.json"
);

#[must_use]
pub fn contract_digest() -> Digest {
    Digest::from_bytes(CONTRACT_JSON.as_bytes())
}

/// Compile-time authority marker for audits and adversarial tests.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReadOnlyAuthority;

impl ReadOnlyAuthority {
    pub const fn external_writes() -> bool {
        false
    }

    pub const fn payment_initiation() -> bool {
        false
    }

    pub const fn checkout() -> bool {
        false
    }

    pub const fn subscription_mutation() -> bool {
        false
    }

    pub const fn transaction_mutation() -> bool {
        false
    }

    pub const fn refund() -> bool {
        false
    }

    pub const fn customer_portal() -> bool {
        false
    }

    pub const fn webhook_effect() -> bool {
        false
    }

    pub const fn durable_native_receipt() -> bool {
        false
    }

    pub const fn independent_readback() -> bool {
        false
    }

    pub const fn kernel_authority() -> bool {
        false
    }

    pub const fn outcome_adoption() -> bool {
        false
    }

    pub const fn connected() -> bool {
        false
    }

    pub const fn native() -> bool {
        false
    }

    pub const fn first_party() -> bool {
        false
    }
}

// Compatibility aliases keep the typed seam discoverable under both the
// provider-centric and subscription-centric vocabulary used by Layer-1 hosts.
pub type PaddleSubscriptionScope = PaddleBillingScope;
pub type PaddleSubscriptionScopeIdentity = PaddleBillingScopeIdentity;
pub type PaddleSubscriptionRegistration = PaddleBillingRegistration;
pub type PaddleSubscriptionEvidence = PaddleBillingEvidence;
pub type PaddleSubscriptionResultProposal = PaddleBillingResultProposal;
pub type PaddleSubscriptionProviderDefinition = PaddleBillingProviderDefinition;
pub type PaddleSubscriptionHttpResponse = PaddleHttpResponse;
pub type RecordingPaddleSubscriptionTransport = RecordingPaddleBillingTransport;

#[cfg(test)]
mod contract_tests {
    use serde_json::Value;

    use super::*;

    #[test]
    fn embedded_contract_is_exactly_layer_one_and_read_only() {
        let document: Value = serde_json::from_str(CONTRACT_JSON).expect("contract JSON");
        assert_eq!(document["schemaVersion"], SCHEMA_VERSION);
        assert_eq!(document["contractVersion"], CONTRACT_VERSION);
        assert_eq!(document["plugin"]["id"], PLUGIN_ID);
        assert_eq!(document["plugin"]["version"], PLUGIN_VERSION);
        assert_eq!(document["layer"], 1);
        assert_eq!(document["service"]["type"], SERVICE_ID);
        assert_eq!(document["provider"]["type"], "PaddleBillingProvider");
        assert_eq!(document["consumer"]["type"], CONSUMER_ID);
        assert_eq!(document["provider"]["apiVersion"], PADDLE_API_VERSION);
        assert_eq!(document["provider"]["nativeStatus"], BLOCKED_ENV);
        assert_eq!(document["provider"]["connected"], false);
        assert_eq!(document["provider"]["native"], false);
        assert_eq!(document["provider"]["firstParty"], false);
        assert_eq!(document["evidence"]["connected"], false);
        assert_eq!(document["evidence"]["native"], false);
        assert_eq!(document["evidence"]["firstParty"], false);
        assert_eq!(document["service"]["paymentInitiation"], false);
        assert_eq!(document["authority"]["connected"], false);
        assert_eq!(contract_digest().as_str().len(), 64);
        assert!(!ReadOnlyAuthority::external_writes());
        assert!(!ReadOnlyAuthority::payment_initiation());
        assert!(!ReadOnlyAuthority::checkout());
        assert!(!ReadOnlyAuthority::subscription_mutation());
        assert!(!ReadOnlyAuthority::transaction_mutation());
        assert!(!ReadOnlyAuthority::refund());
        assert!(!ReadOnlyAuthority::customer_portal());
        assert!(!ReadOnlyAuthority::webhook_effect());
        assert!(!ReadOnlyAuthority::durable_native_receipt());
        assert!(!ReadOnlyAuthority::independent_readback());
        assert!(!ReadOnlyAuthority::kernel_authority());
        assert!(!ReadOnlyAuthority::outcome_adoption());
        assert!(!ReadOnlyAuthority::connected());
        assert!(!ReadOnlyAuthority::native());
        assert!(!ReadOnlyAuthority::first_party());
    }
}
