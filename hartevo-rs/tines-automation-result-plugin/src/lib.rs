//! Standalone Layer-1 governed Tines automation-result boundary.
//!
//! The crate models bounded, read-only Tines story/run/action/event/case and
//! audit metadata for a Mission-scoped proposal. Credentials, raw payloads,
//! inputs, outputs, logs, external writes, kernel authority, durable native
//! receipts, and Outcome adoption remain outside this layer.

#![forbid(unsafe_code)]
#![allow(
    clippy::assigning_clones,
    clippy::collapsible_if,
    clippy::format_push_string,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::missing_fields_in_debug,
    clippy::needless_pass_by_value,
    clippy::redundant_closure_for_method_calls,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]

use sha2::{Digest as ShaDigest, Sha256};

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    MissionTinesAutomationConsumer, MissionTinesAutomationResult, ProposalDisposition,
    RecordedTinesAutomationResult,
};
pub use error::{Result, TinesAutomationResultError, TinesAutomationResultErrorKind};
pub use model::*;
pub use provider::{
    BlockedEnvTransport, FixtureTransport, LoopbackTransport, RecordingTransport, TinesProvider,
    TinesProviderDefinition, TinesRequest, TinesResponse, TinesTransport, TinesTransportError,
};
pub use service::{
    TinesAutomationResultService, TinesAutomationResultServiceDefinition,
    TinesAutomationResultServiceError, TinesServiceError,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.tines-automation-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-TINES-01-L1/v1";
pub const PLUGIN_ID: &str = "tines.automation-result";
pub const PLUGIN_VERSION: &str = "0.1.0";
pub const SERVICE_ID: &str = "tines.automation-result.read";
pub const SERVICE_VERSION: &str = "1.0.0";
pub const PROVIDER_ID: &str = "tines.api.automation-result";
pub const PROVIDER_VERSION: &str = "1.0.0";
pub const PROVIDER_API_REVISION: &str = "tines-api-v1-bounded-read-2026-08";
pub const CONSUMER_ID: &str = "mission.tines-automation-result";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";

pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_TIME_WINDOW_DAYS: i64 = 31;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: u16 = 4;
pub const MAX_AUDIT_LOGS: usize = MAX_PAGE_SIZE as usize * MAX_PAGES as usize;
pub const MAX_REQUESTS_PER_READ: usize = 6;
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_RETRY_AFTER_SECONDS: u32 = 3_600;
pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/tines-automation-result/tines-automation-result.v1.json"
);

#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[must_use]
pub fn contract_digest() -> String {
    sha256_hex(CONTRACT_JSON.as_bytes())
}

/// Layer 1 deliberately reports no native or kernel authority.
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
    pub const fn kernel_authority() -> bool {
        false
    }

    #[must_use]
    pub const fn outcome_authority() -> bool {
        false
    }

    #[must_use]
    pub const fn external_writes() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_tests {
    use serde_json::Value;

    use super::{
        CONSUMER_ID, CONTRACT_JSON, CONTRACT_SCHEMA, CONTRACT_VERSION, Layer1Authority, PLUGIN_ID,
        PROVIDER_ID, SERVICE_ID, contract_digest,
    };

    #[test]
    fn checked_contract_is_machine_readable_and_layer_one_honest() {
        let contract: Value = serde_json::from_str(CONTRACT_JSON).expect("Tines contract JSON");
        assert_eq!(contract["schemaVersion"], CONTRACT_SCHEMA);
        assert_eq!(contract["contractVersion"], CONTRACT_VERSION);
        assert_eq!(contract["pluginId"], PLUGIN_ID);
        assert_eq!(contract["layer"], 1);
        assert_eq!(contract["service"]["id"], SERVICE_ID);
        assert_eq!(contract["provider"]["id"], PROVIDER_ID);
        assert_eq!(contract["consumer"]["id"], CONSUMER_ID);
        assert_eq!(contract["authority"]["connected"], false);
        assert_eq!(contract["authority"]["nativeProvider"], false);
        assert_eq!(contract["authority"]["firstParty"], false);
        assert_eq!(contract["authority"]["externalWrites"], false);
        assert_eq!(
            contract["allowlist"]["writes"].as_array().map(Vec::len),
            Some(0)
        );
        assert!(!contract_digest().is_empty());
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::durable_receipt());
        assert!(!Layer1Authority::kernel_authority());
        assert!(!Layer1Authority::outcome_authority());
        assert!(!Layer1Authority::external_writes());
    }
}
