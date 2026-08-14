//! Layer-1 Anthropic Claude Messages result proposal and recording seam.
//!
//! The crate binds one exact account/workspace/model/version/request and
//! Project/Mission/Work Product scope. It projects only bounded response
//! metadata, stop reason, usage, latency, refusal/citation metadata, and
//! content digests. It does not resolve API keys, retain prompts/output or
//! thinking, execute tools, upload files, administer batches, create models,
//! issue kernel receipts, or adopt an Outcome.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;
pub mod transport;

pub use consumer::{MissionAnthropicResult, MissionAnthropicResultConsumer};
pub use error::{AnthropicMessageResultError, Result};
pub use model::*;
pub use provider::{
    AnthropicProvider, BlockedEnvCode, ProviderResponseOutcome, RecordedAnthropicResponse,
};
pub use service::{AnthropicMessageResultService, AnthropicServiceDefinition};
pub use transport::{
    AnthropicHttpRequest, AnthropicTransport, BlockedEnvAnthropicTransport, FakeAnthropicTransport,
    FixtureAnthropicTransport, LoopbackAnthropicTransport, NativeAnthropicTransport,
    RecordingAnthropicTransport, TransportOutcome, allowlisted_request,
};

pub const SCHEMA_VERSION: &str = "hartevo.anthropic-message-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-ANTHROPIC-01-L1/v1";
pub const PLUGIN_ID: &str = "hartevo.anthropic-message-result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const PROVIDER_ID: &str = "AnthropicProvider";
pub const SERVICE_ID: &str = "AnthropicMessageResultService";
pub const CONSUMER_ID: &str = "MissionAnthropicResultConsumer";
pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/anthropic-message-result/anthropic-message-result.v1.json"
);
pub const NATIVE_GAP: &str = "BLOCKED_ENV: native API-key resolution, live Anthropic HTTPS transport, durable provider receipts, independent output read-back, and verified Work Product adoption remain Layer-2 gaps";

pub fn contract_digest() -> Digest {
    Digest::from_bytes(CONTRACT_JSON.as_bytes())
}

/// Validate the frozen contract document against the code-level constants and
/// authority promises. This is intentionally dependency-light so it can be
/// run as a local contract gate in the standalone workspace.
pub fn validate_contract() -> Result<()> {
    let document: serde_json::Value = serde_json::from_str(CONTRACT_JSON)
        .map_err(|_| AnthropicMessageResultError::MalformedResponse("contract JSON is invalid"))?;
    let expected = [
        ("schemaVersion", SCHEMA_VERSION),
        ("contractVersion", CONTRACT_VERSION),
        ("pluginVersion", PLUGIN_VERSION),
    ];
    if expected
        .iter()
        .any(|(key, value)| document[*key].as_str() != Some(*value))
        || document["layer"].as_u64() != Some(1)
        || document["service"]["readOnly"] != true
        || document["service"]["proposalOnly"] != true
        || document["service"]["recordingOnly"] != true
        || document["service"]["externalWrites"] != false
        || document["service"]["durableReceipts"] != false
        || document["service"]["kernelTruthAuthority"] != false
        || document["service"]["kernelEffectAuthority"] != false
        || document["service"]["kernelReceiptAuthority"] != false
        || document["service"]["kernelVerificationAuthority"] != false
        || document["service"]["kernelOutcomeAuthority"] != false
        || document["service"]["workProductAdoption"] != false
        || document["provider"]["nativeStatus"] != "BLOCKED_ENV"
        || document["provider"]["connectedEvidence"] != false
        || document["provider"]["nativeEvidence"] != false
        || document["redaction"]["rawPrompt"] != false
        || document["redaction"]["rawOutput"] != false
        || document["redaction"]["thinking"] != false
        || document["authority"]["connected"] != false
        || document["authority"]["native"] != false
        || document["authority"]["externalWrites"] != false
        || document["authority"]["kernelOutcome"] != false
    {
        return Err(AnthropicMessageResultError::MutationForbidden(
            "contract authority or identity drift",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn contract_is_layer_one_and_native_honest() {
        validate_contract().expect("valid Anthropic contract");
        assert_eq!(contract_digest().as_str().len(), 64);
        assert_eq!(ANTHROPIC_MESSAGES_METHOD, "POST");
        assert_eq!(ANTHROPIC_MESSAGES_PATH, "/v1/messages");
        assert!(!ProviderProvenance::Fixture.connected());
        assert!(!ProviderProvenance::Recording.native());
        assert!(!ProviderProvenance::BlockedEnv.first_party());
        assert!(!Layer1Authority::layer_one().connected);
    }
}
