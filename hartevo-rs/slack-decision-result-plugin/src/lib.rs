//! Standalone Layer-1 governed Slack collaboration-decision result plugin.
//!
//! This crate exposes typed scope, provider, bounded read, proposal, record,
//! verification, and Mission-consumption seams. It deliberately does not
//! resolve Slack credentials, make native HTTPS requests, store transcripts,
//! mutate Slack, create a durable native receipt, or adopt a Work Product or
//! kernel Outcome.

#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;

use thiserror::Error;

pub use consumer::{
    ConsumerError, MissionSlackDecisionConsumer, MissionSlackDecisionResult, SlackDecisionState,
};
pub use model::*;
pub use provider::{
    BlockedEnvSlackTransport, BlockedEnvTransport, FakeSlackTransport, FixtureSlackTransport,
    LoopbackSlackTransport, ProviderDefinitionError, RecordingSlackTransport, SlackProvider,
    SlackProviderError, SlackProviderIdentity, SlackTransport,
};
pub use service::{
    RegistrationError, RegistrationState, SlackCapabilities, SlackDecisionEvidence,
    SlackDecisionProposal, SlackDecisionRecord, SlackDecisionService, SlackDecisionServiceError,
    SlackEvidenceState, SlackReadResult, SlackRegistration, SlackVerifiedDecision,
};

pub const SLACK_DECISION_SCHEMA_VERSION: &str = "hartevo.slack-decision-result.contract/v1";
pub const SLACK_DECISION_CONTRACT_VERSION: &str = "slack-decision-result/v1";
pub const SLACK_DECISION_PLUGIN_VERSION: &str = "1.0.0";
pub const SLACK_DECISION_SERVICE_ID: &str = "slack.decision.result";
pub const SLACK_DECISION_PROVIDER_ID: &str = "slack.conversations.read";
pub const SLACK_DECISION_PROVIDER_VERSION: &str = "1.0.0";
pub const SLACK_DECISION_API_REVISION: &str = "slack-conversations-read-r1";
pub const SLACK_DECISION_CONSUMER_ID: &str = "mission.slack.decision-result";
pub const SLACK_DECISION_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const SLACK_DECISION_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/slack-decision-result/slack-decision-result.v1.json");

pub fn contract_digest() -> Digest {
    Digest::from_bytes(SLACK_DECISION_CONTRACT_JSON.as_bytes())
}

pub const fn plugin_version() -> (u16, u16, u16) {
    (1, 0, 0)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlackDecisionContract {
    value: serde_json::Value,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ContractError {
    #[error("Slack decision contract JSON is invalid: {0}")]
    InvalidJson(String),
    #[error("Slack decision contract shape is invalid: {0}")]
    Shape(&'static str),
    #[error("Slack decision contract identity is invalid: {0}")]
    Identity(&'static str),
}

impl SlackDecisionContract {
    pub fn baseline() -> Result<Self, ContractError> {
        let value = serde_json::from_str::<serde_json::Value>(SLACK_DECISION_CONTRACT_JSON)
            .map_err(|error| ContractError::InvalidJson(error.to_string()))?;
        let contract = Self { value };
        contract.validate()?;
        Ok(contract)
    }

    pub fn value(&self) -> &serde_json::Value {
        &self.value
    }

    pub fn digest(&self) -> Digest {
        contract_digest()
    }

    pub fn validate(&self) -> Result<(), ContractError> {
        let object = self
            .value
            .as_object()
            .ok_or(ContractError::Shape("contract is not an object"))?;
        for key in [
            "$schema",
            "$id",
            "schemaVersion",
            "contractVersion",
            "pluginVersion",
            "layer",
            "service",
            "provider",
            "consumer",
            "scope",
            "registration",
            "bounds",
            "evidence",
            "redaction",
            "transport",
            "authority",
            "honesty",
            "layer2Gaps",
            "forbidden",
        ] {
            if !object.contains_key(key) {
                return Err(ContractError::Shape("required contract key missing"));
            }
        }
        if object
            .get("schemaVersion")
            .and_then(serde_json::Value::as_str)
            != Some(SLACK_DECISION_SCHEMA_VERSION)
            || object
                .get("contractVersion")
                .and_then(serde_json::Value::as_str)
                != Some(SLACK_DECISION_CONTRACT_VERSION)
            || object
                .get("pluginVersion")
                .and_then(serde_json::Value::as_str)
                != Some(SLACK_DECISION_PLUGIN_VERSION)
            || object.get("layer").and_then(serde_json::Value::as_str) != Some("Layer-1")
        {
            return Err(ContractError::Identity("contract identity drifted"));
        }
        let service = object
            .get("service")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractError::Shape("service is not an object"))?;
        if service.get("id").and_then(serde_json::Value::as_str) != Some(SLACK_DECISION_SERVICE_ID)
            || service
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some("SlackDecisionService")
            || service.get("readOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("proposalOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("liveExecution") != Some(&serde_json::Value::Bool(false))
            || service.get("externalWrites") != Some(&serde_json::Value::Bool(false))
        {
            return Err(ContractError::Identity("service identity drifted"));
        }
        let provider = object
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractError::Shape("provider is not an object"))?;
        if provider.get("id").and_then(serde_json::Value::as_str)
            != Some(SLACK_DECISION_PROVIDER_ID)
            || provider
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some("SlackProvider")
            || provider.get("native") != Some(&serde_json::Value::Bool(false))
            || provider.get("connected") != Some(&serde_json::Value::Bool(false))
            || provider.get("firstParty") != Some(&serde_json::Value::Bool(false))
            || provider.get("externalWrites") != Some(&serde_json::Value::Bool(false))
            || provider.get("rawMessageExport") != Some(&serde_json::Value::Bool(false))
            || provider.get("rawAttachmentExport") != Some(&serde_json::Value::Bool(false))
        {
            return Err(ContractError::Identity("provider identity drifted"));
        }
        let consumer = object
            .get("consumer")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractError::Shape("consumer is not an object"))?;
        if consumer.get("id").and_then(serde_json::Value::as_str)
            != Some(SLACK_DECISION_CONSUMER_ID)
            || consumer
                .get("implementation")
                .and_then(serde_json::Value::as_str)
                != Some("MissionSlackDecisionConsumer")
            || consumer.get("adoptsOutcome") != Some(&serde_json::Value::Bool(false))
            || consumer.get("truthAuthority") != Some(&serde_json::Value::Bool(false))
        {
            return Err(ContractError::Identity("consumer identity drifted"));
        }
        let transport = object
            .get("transport")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractError::Shape("transport is not an object"))?;
        for key in ["connected", "native", "firstParty"] {
            if transport.get(key) != Some(&serde_json::Value::Bool(false)) {
                return Err(ContractError::Identity("transport claims drifted"));
            }
        }
        let authority = object
            .get("authority")
            .and_then(serde_json::Value::as_object)
            .ok_or(ContractError::Shape("authority is not an object"))?;
        for key in [
            "externalWrites",
            "chatPostMessage",
            "reactionMutation",
            "channelMutation",
            "memberMutation",
            "rawTranscriptExport",
            "kernelAuthority",
            "consentAuthority",
            "effectAuthority",
            "receiptAuthority",
            "verificationAuthority",
            "workProductAdoption",
            "connected",
            "native",
            "durableNativeReceipt",
        ] {
            if authority.get(key) != Some(&serde_json::Value::Bool(false)) {
                return Err(ContractError::Identity("authority claims drifted"));
            }
        }
        Ok(())
    }
}

/// The authority boundary exposed by this Layer-1 root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    pub const fn connected() -> bool {
        false
    }

    pub const fn native_provider() -> bool {
        false
    }

    pub const fn first_party() -> bool {
        false
    }

    pub const fn durable_native_receipt() -> bool {
        false
    }

    pub const fn kernel_authority() -> bool {
        false
    }

    pub const fn work_product_adoption() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_document_tests {
    use super::{
        Layer1Authority, SLACK_DECISION_BLOCKED_ENV, SLACK_DECISION_CONSUMER_ID,
        SLACK_DECISION_CONTRACT_VERSION, SLACK_DECISION_PROVIDER_ID, SLACK_DECISION_SCHEMA_VERSION,
        SLACK_DECISION_SERVICE_ID, SlackDecisionContract,
    };

    #[test]
    fn contract_is_layer_one_and_never_native() {
        let contract = SlackDecisionContract::baseline().expect("contract");
        let value = contract.value();
        assert_eq!(
            value["schemaVersion"].as_str(),
            Some(SLACK_DECISION_SCHEMA_VERSION)
        );
        assert_eq!(
            value["contractVersion"].as_str(),
            Some(SLACK_DECISION_CONTRACT_VERSION)
        );
        assert_eq!(
            value["service"]["id"].as_str(),
            Some(SLACK_DECISION_SERVICE_ID)
        );
        assert_eq!(
            value["provider"]["id"].as_str(),
            Some(SLACK_DECISION_PROVIDER_ID)
        );
        assert_eq!(
            value["consumer"]["id"].as_str(),
            Some(SLACK_DECISION_CONSUMER_ID)
        );
        assert_eq!(value["transport"]["native"], false);
        assert_eq!(value["transport"]["connected"], false);
        assert_eq!(value["transport"]["firstParty"], false);
        assert_eq!(value["transport"]["blockedEnv"], true);
        assert_eq!(value["authority"]["externalWrites"], false);
        assert_eq!(value["authority"]["rawTranscriptExport"], false);
        assert_eq!(SLACK_DECISION_BLOCKED_ENV, "BLOCKED_ENV");
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::durable_native_receipt());
        assert!(!Layer1Authority::kernel_authority());
        assert!(!Layer1Authority::work_product_adoption());
    }
}
