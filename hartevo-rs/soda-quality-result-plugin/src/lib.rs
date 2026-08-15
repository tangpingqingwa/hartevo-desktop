//! Standalone Layer-1 governed Soda data-quality result plugin.
//!
//! The crate exposes typed, bounded read/proposal/recording seams for
//! [`SodaQualityResultService`], [`SodaProvider`], and
//! [`MissionSodaQualityConsumer`]. It never resolves native credentials,
//! executes a check or scan, exports raw rows or response bodies, claims data
//! correctness, creates a durable provider receipt, or adopts a Work Product.

#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::if_not_else)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::result_large_err)]
#![allow(clippy::similar_names)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::struct_excessive_bools)]

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    MissionSodaQualityConsumer, MissionSodaQualityRecord, MissionSodaQualityResult,
    MissionSodaQualityResultState, RecordedMissionSodaQualityResult,
};
pub use error::{Result, SodaQualityResultError, SodaTransportError};
pub use model::*;
pub use provider::{
    BlockedEnvSodaTransport, BlockedEnvTransport, CheckRequest, DatasetRequest, FakeSodaTransport,
    FakeTransport, FixtureSodaTransport, FixtureTransport, LoopbackSodaTransport,
    LoopbackTransport, QualityHealthRequest, RecordingSodaTransport, RecordingTransport,
    ScanRequest, SodaCheckRequest, SodaCheckResponse, SodaDatasetRequest, SodaDatasetResponse,
    SodaProvider, SodaProviderDefinition, SodaProviderError, SodaProviderReadKind,
    SodaQualityHealthRequest, SodaQualityHealthResponse, SodaReadRequest, SodaScanRequest,
    SodaScanResponse, SodaTransport,
};
pub use service::{
    SodaQualityResultService, SodaQualityResultServiceError, SodaRecordedResult, SodaService,
    SodaVerificationFailure, SodaVerificationReport, VerificationFailure, VerificationReport,
};

pub type SodaQualityResultProvider<T> = SodaProvider<T>;
pub type SodaQualityResultConsumer = MissionSodaQualityConsumer;

pub const CONTRACT_SCHEMA: &str = "hartevo.soda-quality-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-SODA-01-L1/v1";
pub const PLUGIN_VERSION: &str = "0.1.0";
pub const PLUGIN_ID: &str = "soda.quality.result";
pub const SERVICE_ID: &str = "soda.quality.result.read";
pub const PROVIDER_ID: &str = "soda.reporting.quality.result.recording";
pub const CONSUMER_ID: &str = "mission.soda.quality.result";
pub const API_REVISION: &str = "soda-reporting-dataset-check-scan-quality-health-v1";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.soda-quality-result/v1|layer=1|service=soda.quality.result.read|provider=soda.reporting.quality.result.recording|consumer=mission.soda.quality.result|api=soda-reporting-dataset-check-scan-quality-health-v1";
pub const CONTRACT_DIGEST: &str =
    "abf9758806b08d49367e9873c2bfc913ccf93ff69c3d3819550687a7d54c6ce1";
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/soda-quality-result/soda-quality-result.v1.json");

#[must_use]
pub fn contract_digest() -> Digest {
    Digest::parse(CONTRACT_DIGEST.to_owned()).expect("checked-in Soda contract digest")
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
    pub const fn kernel_authority() -> bool {
        false
    }

    #[must_use]
    pub const fn outcome_authority() -> bool {
        false
    }

    #[must_use]
    pub const fn data_correctness_authority() -> bool {
        false
    }

    #[must_use]
    pub const fn external_writes() -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SodaQualityResultContract {
    value: serde_json::Value,
}

impl SodaQualityResultContract {
    pub fn baseline() -> Result<Self> {
        let value = serde_json::from_str::<serde_json::Value>(CONTRACT_JSON)
            .map_err(|_| SodaQualityResultError::ContractDrift)?;
        let contract = Self { value };
        contract.validate()?;
        Ok(contract)
    }

    #[must_use]
    pub fn value(&self) -> &serde_json::Value {
        &self.value
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        contract_digest()
    }

    pub fn validate(&self) -> Result<()> {
        let object = self
            .value
            .as_object()
            .ok_or(SodaQualityResultError::ContractDrift)?;
        for key in [
            "$schema",
            "$id",
            "schemaVersion",
            "contractVersion",
            "pluginVersion",
            "pluginId",
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
            "registration",
            "evidence",
            "provenance",
            "forbiddenEffects",
            "authorityBoundary",
            "layer2Gaps",
        ] {
            if !object.contains_key(key) {
                return Err(SodaQualityResultError::ContractDrift);
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
            || object
                .get("pluginVersion")
                .and_then(serde_json::Value::as_str)
                != Some(PLUGIN_VERSION)
            || object.get("pluginId").and_then(serde_json::Value::as_str) != Some(PLUGIN_ID)
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
                != Some(CONTRACT_DIGEST)
        {
            return Err(SodaQualityResultError::ContractDrift);
        }
        let authority = object
            .get("authority")
            .and_then(serde_json::Value::as_object)
            .ok_or(SodaQualityResultError::ContractDrift)?;
        for key in [
            "connected",
            "native",
            "firstParty",
            "durableProviderReceipt",
            "kernelAuthority",
            "truthAuthority",
            "outcomeAuthority",
            "workProductAdoption",
            "dataCorrectnessCertification",
            "externalWrites",
        ] {
            if authority.get(key) != Some(&serde_json::Value::Bool(false)) {
                return Err(SodaQualityResultError::ContractDrift);
            }
        }
        let provider = object
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .ok_or(SodaQualityResultError::ContractDrift)?;
        if provider.get("id").and_then(serde_json::Value::as_str) != Some(PROVIDER_ID)
            || provider
                .get("apiRevision")
                .and_then(serde_json::Value::as_str)
                != Some(API_REVISION)
            || provider.get("connected") != Some(&serde_json::Value::Bool(false))
            || provider.get("native") != Some(&serde_json::Value::Bool(false))
            || provider.get("firstParty") != Some(&serde_json::Value::Bool(false))
            || provider.get("providerReceipt") != Some(&serde_json::Value::Bool(false))
        {
            return Err(SodaQualityResultError::ContractDrift);
        }
        let service = object
            .get("service")
            .and_then(serde_json::Value::as_object)
            .ok_or(SodaQualityResultError::ContractDrift)?;
        if service.get("id").and_then(serde_json::Value::as_str) != Some(SERVICE_ID)
            || service.get("checkExecution") != Some(&serde_json::Value::Bool(false))
            || service.get("externalWrites") != Some(&serde_json::Value::Bool(false))
        {
            return Err(SodaQualityResultError::ContractDrift);
        }
        let consumer = object
            .get("consumer")
            .and_then(serde_json::Value::as_object)
            .ok_or(SodaQualityResultError::ContractDrift)?;
        if consumer.get("id").and_then(serde_json::Value::as_str) != Some(CONSUMER_ID)
            || consumer.get("adoptsOutcome") != Some(&serde_json::Value::Bool(false))
            || consumer.get("adoptsWorkProduct") != Some(&serde_json::Value::Bool(false))
        {
            return Err(SodaQualityResultError::ContractDrift);
        }
        Ok(())
    }
}

#[cfg(test)]
mod contract_document_tests {
    use super::{
        API_REVISION, BLOCKED_ENV, CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_DIGEST_INPUT,
        CONTRACT_JSON, CONTRACT_SCHEMA, CONTRACT_VERSION, EVIDENCE_LEVEL, Layer1Authority,
        PLUGIN_ID, PLUGIN_VERSION, PROVIDER_ID, SERVICE_ID, SodaQualityResultContract,
        contract_digest,
    };

    #[test]
    fn contract_is_machine_readable_and_layer_one_honest() {
        let document: serde_json::Value =
            serde_json::from_str(CONTRACT_JSON).expect("contract JSON");
        assert_eq!(document["schemaVersion"], CONTRACT_SCHEMA);
        assert_eq!(document["contractVersion"], CONTRACT_VERSION);
        assert_eq!(document["pluginVersion"], PLUGIN_VERSION);
        assert_eq!(document["pluginId"], PLUGIN_ID);
        assert_eq!(document["evidenceLevel"], EVIDENCE_LEVEL);
        assert_eq!(document["digestInput"], CONTRACT_DIGEST_INPUT);
        assert_eq!(document["contractDigest"], CONTRACT_DIGEST);
        assert_eq!(document["service"]["id"], SERVICE_ID);
        assert_eq!(document["provider"]["id"], PROVIDER_ID);
        assert_eq!(document["provider"]["apiRevision"], API_REVISION);
        assert_eq!(document["consumer"]["id"], CONSUMER_ID);
        assert_eq!(document["authority"]["connected"], false);
        assert_eq!(document["authority"]["native"], false);
        assert_eq!(document["authority"]["externalWrites"], false);
        assert_eq!(
            document["provider"]["authentication"]["rawTokenSerialized"],
            false
        );
        assert_eq!(document["provider"]["transportProvenance"][4], BLOCKED_ENV);
        assert_eq!(contract_digest().as_str(), CONTRACT_DIGEST);
        SodaQualityResultContract::baseline().expect("valid Soda contract");
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::durable_provider_receipt());
        assert!(!Layer1Authority::kernel_authority());
        assert!(!Layer1Authority::outcome_authority());
        assert!(!Layer1Authority::data_correctness_authority());
        assert!(!Layer1Authority::external_writes());
    }
}
