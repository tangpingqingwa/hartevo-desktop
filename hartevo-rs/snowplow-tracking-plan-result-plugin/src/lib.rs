//! Standalone Layer-1 governed Snowplow Event Studio evidence boundary.
//!
//! The crate exposes typed, bounded reads for tracking plans, event
//! specifications, and tracking-plan history. It deliberately stops at a
//! digest-only proposal/observation seam: it does not resolve credentials,
//! open native HTTPS, ingest or replay events, manage subscriptions, mutate a
//! plan, export telemetry or identity data, create kernel receipts, or adopt
//! an Outcome.

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

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    MissionSnowplowConsumer, MissionSnowplowTrackingPlanConsumer,
    MissionSnowplowTrackingPlanResult, RecordedSnowplowTrackingPlanResult,
};
pub use model::*;
pub use provider::{
    BlockedEnvSnowplowTransport, FixtureSnowplowTransport, LoopbackSnowplowTransport,
    RecordingSnowplowTransport, SnowplowApiResponse, SnowplowOperation, SnowplowProvider,
    SnowplowProviderDefinition, SnowplowProviderError, SnowplowProviderPage, SnowplowRequest,
    SnowplowTransport, SnowplowTransportError,
};
pub use service::{
    SnowplowReadOptions, SnowplowServiceError, SnowplowTrackingPlanProposal,
    SnowplowTrackingPlanService, SnowplowTrackingPlanServiceDefinition, SnowplowVerificationReport,
};

pub type SnowplowService<T> = SnowplowTrackingPlanService<T>;
pub type SnowplowTrackingPlanProvider<T> = SnowplowProvider<T>;
pub type SnowplowTrackingPlanResult = SnowplowTrackingPlanProposal;
pub type MissionSnowplowResult = MissionSnowplowTrackingPlanResult;

pub const CONTRACT_SCHEMA: &str = "hartevo.snowplow-tracking-plan/v1";
pub const CONTRACT_VERSION: &str = "EXT-SNOWPLOW-01-L1/v1";
pub const PLUGIN_ID: &str = "snowplow.tracking-plan";
pub const PLUGIN_VERSION: &str = "0.1.0";
pub const SERVICE_ID: &str = "snowplow.tracking-plan.evidence.read";
pub const PROVIDER_ID: &str = "snowplow.console.tracking-plan.read";
pub const CONSUMER_ID: &str = "mission.snowplow.tracking-plan";
pub const API_REVISION: &str = "console-tracking-plans-event-specs-history-v1-r1";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const SNOWPLOW_HOST: &str = "https://console.snowplowanalytics.com";
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.snowplow-tracking-plan/v1|layer=1|service=snowplow.tracking-plan.evidence.read|provider=snowplow.console.tracking-plan.read|consumer=mission.snowplow.tracking-plan|api=console-tracking-plans-event-specs-history-v1-r1";
pub const CONTRACT_DIGEST: &str =
    "d7283a4a0cd4a669d8ccb857310f83cc73a22ae9efe9038e847718cdb8f79606";
pub const CONTRACT_PATH: &str =
    "contracts/plugins/snowplow-tracking-plan-result/snowplow-tracking-plan.v1.json";
pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/snowplow-tracking-plan-result/snowplow-tracking-plan.v1.json"
);

/// Layer-1 permissions are intentionally narrower than a Snowplow Console
/// API key. No mutation, subscription, collector, or telemetry permission is
/// represented by this crate.
pub const LAYER1_PERMISSIONS: [&str; 3] = [
    "snowplow.tracking_plan.read",
    "snowplow.event_spec.read",
    "snowplow.tracking_plan.history.read",
];

#[must_use]
pub fn contract_digest() -> String {
    CONTRACT_DIGEST.to_owned()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnowplowContract {
    value: serde_json::Value,
}

impl SnowplowContract {
    pub fn baseline() -> Result<Self, SnowplowContractError> {
        let value =
            serde_json::from_str(CONTRACT_JSON).map_err(|_| SnowplowContractError::InvalidJson)?;
        let contract = Self { value };
        contract.validate()?;
        Ok(contract)
    }

    #[must_use]
    pub const fn value(&self) -> &serde_json::Value {
        &self.value
    }

    pub fn validate(&self) -> Result<(), SnowplowContractError> {
        let object = self
            .value
            .as_object()
            .ok_or(SnowplowContractError::MissingField("root"))?;
        for key in [
            "schemaVersion",
            "contractVersion",
            "pluginId",
            "pluginVersion",
            "layer",
            "evidenceLevel",
            "digestInput",
            "contractDigest",
            "authority",
            "typedSurface",
            "service",
            "provider",
            "consumer",
            "scope",
            "pagination",
            "normalization",
            "receipts",
            "digests",
            "registration",
            "allowlist",
            "honesty",
            "authorityBoundary",
            "documentation",
            "layer2Gaps",
        ] {
            if !object.contains_key(key) {
                return Err(SnowplowContractError::MissingField(key));
            }
        }
        if object
            .get("schemaVersion")
            .and_then(serde_json::Value::as_str)
            != Some(CONTRACT_SCHEMA)
            || object
                .get("contractVersion")
                .and_then(serde_json::Value::as_str)
                != Some(CONTRACT_VERSION)
            || object.get("pluginId").and_then(serde_json::Value::as_str) != Some(PLUGIN_ID)
            || object
                .get("pluginVersion")
                .and_then(serde_json::Value::as_str)
                != Some(PLUGIN_VERSION)
            || object.get("layer").and_then(serde_json::Value::as_str) != Some("Layer-1")
            || object
                .get("evidenceLevel")
                .and_then(serde_json::Value::as_str)
                != Some(EVIDENCE_LEVEL)
            || object
                .get("digestInput")
                .and_then(serde_json::Value::as_str)
                != Some(CONTRACT_DIGEST_INPUT)
            || object
                .get("contractDigest")
                .and_then(serde_json::Value::as_str)
                != Some(contract_digest().as_str())
        {
            return Err(SnowplowContractError::ContractDrift);
        }
        let authority = object
            .get("authority")
            .and_then(serde_json::Value::as_object)
            .ok_or(SnowplowContractError::MissingField("authority"))?;
        for key in [
            "readOnly",
            "proposalOnly",
            "connected",
            "native",
            "firstParty",
            "externalWrites",
            "subscriptions",
            "eventIngestion",
            "eventReplay",
            "rawTelemetry",
            "rawIdentity",
        ] {
            if authority.get(key).is_none() {
                return Err(SnowplowContractError::MissingField(key));
            }
        }
        for key in [
            "connected",
            "native",
            "firstParty",
            "externalWrites",
            "subscriptions",
            "eventIngestion",
            "eventReplay",
            "rawTelemetry",
            "rawIdentity",
        ] {
            if authority.get(key) != Some(&serde_json::Value::Bool(false)) {
                return Err(SnowplowContractError::ContractDrift);
            }
        }
        let provider = object
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .ok_or(SnowplowContractError::MissingField("provider"))?;
        if provider.get("id").and_then(serde_json::Value::as_str) != Some(PROVIDER_ID)
            || provider
                .get("apiRevision")
                .and_then(serde_json::Value::as_str)
                != Some(API_REVISION)
            || provider.get("native") != Some(&serde_json::Value::Bool(false))
            || provider.get("connected") != Some(&serde_json::Value::Bool(false))
            || provider.get("firstParty") != Some(&serde_json::Value::Bool(false))
        {
            return Err(SnowplowContractError::ContractDrift);
        }
        let service = object
            .get("service")
            .and_then(serde_json::Value::as_object)
            .ok_or(SnowplowContractError::MissingField("service"))?;
        if service.get("id").and_then(serde_json::Value::as_str) != Some(SERVICE_ID)
            || service.get("externalWrites") != Some(&serde_json::Value::Bool(false))
        {
            return Err(SnowplowContractError::ContractDrift);
        }
        let consumer = object
            .get("consumer")
            .and_then(serde_json::Value::as_object)
            .ok_or(SnowplowContractError::MissingField("consumer"))?;
        if consumer.get("id").and_then(serde_json::Value::as_str) != Some(CONSUMER_ID)
            || consumer.get("adoptsOutcome") != Some(&serde_json::Value::Bool(false))
            || consumer.get("adoptsWorkProduct") != Some(&serde_json::Value::Bool(false))
        {
            return Err(SnowplowContractError::ContractDrift);
        }
        let writes_empty = object
            .get("allowlist")
            .and_then(serde_json::Value::as_object)
            .and_then(|allowlist| allowlist.get("writes"))
            .and_then(serde_json::Value::as_array)
            .is_some_and(Vec::is_empty);
        if !writes_empty {
            return Err(SnowplowContractError::ContractDrift);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SnowplowContractError {
    #[error("Snowplow contract JSON is invalid")]
    InvalidJson,
    #[error("Snowplow contract field is missing: {0}")]
    MissingField(&'static str),
    #[error("Snowplow contract drifted from the typed Layer-1 surface")]
    ContractDrift,
}

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
    pub const fn durable_provider_receipt() -> bool {
        false
    }

    #[must_use]
    pub const fn adopts_outcome() -> bool {
        false
    }

    #[must_use]
    pub const fn external_writes() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_document_tests {
    use super::{
        API_REVISION, BLOCKED_ENV, CONSUMER_ID, CONTRACT_JSON, CONTRACT_SCHEMA, CONTRACT_VERSION,
        Layer1Authority, PLUGIN_ID, PLUGIN_VERSION, PROVIDER_ID, SERVICE_ID, SnowplowContract,
        contract_digest,
    };

    #[test]
    fn contract_is_machine_readable_and_layer_one_honest() {
        let contract = SnowplowContract::baseline().expect("Snowplow contract");
        let document = contract.value();
        assert_eq!(document["schemaVersion"], CONTRACT_SCHEMA);
        assert_eq!(document["contractVersion"], CONTRACT_VERSION);
        assert_eq!(document["pluginId"], PLUGIN_ID);
        assert_eq!(document["pluginVersion"], PLUGIN_VERSION);
        assert_eq!(document["service"]["id"], SERVICE_ID);
        assert_eq!(document["provider"]["id"], PROVIDER_ID);
        assert_eq!(document["provider"]["apiRevision"], API_REVISION);
        assert_eq!(document["consumer"]["id"], CONSUMER_ID);
        assert_eq!(document["provider"]["transportProvenance"][3], BLOCKED_ENV);
        assert!(!contract_digest().is_empty());
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::durable_provider_receipt());
        assert!(!Layer1Authority::adopts_outcome());
        assert!(!Layer1Authority::external_writes());
        assert!(!CONTRACT_JSON.is_empty());
    }
}
