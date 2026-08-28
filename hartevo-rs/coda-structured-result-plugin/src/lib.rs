//! Standalone Layer-1 Coda structured-result metadata plugin.
//!
//! The crate exposes only bounded, redacted, digest-bound read/proposal seams
//! for Coda API v1 metadata. It never resolves an API token, opens native
//! HTTPS, reads raw rich text or PII, executes formulas, presses buttons,
//! mutates a row/page, registers a generic knowledge source, or adopts a
//! kernel Outcome/Work Product.

#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::if_not_else)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::large_enum_variant)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::result_large_err)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::type_complexity)]

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;
pub mod transport;

pub use consumer::{
    MissionCodaStructuredConsumer, MissionCodaStructuredConsumerError, MissionCodaStructuredResult,
    MissionCodaStructuredResultConsumer,
};
pub use error::{CodaProviderError, CodaResult, CodaStructuredResultError, CodaTransportError};
pub use model::*;
pub use provider::{CodaProvider, CodaProviderCall, CodaProviderDefinition};
pub use service::{
    CodaServiceCapability, CodaServiceOperation, CodaStructuredResultService,
    CodaStructuredResultServiceDefinition, CodaStructuredResultServiceError,
};
pub use transport::{
    BlockedEnvCodaTransport, CodaFakeTransport, CodaFixtureTransport, CodaLoopbackTransport,
    CodaRecordingTransport, CodaTransport, FakeCodaTransport, FixtureCodaTransport,
    LoopbackCodaTransport, RecordingCodaTransport,
};

pub const CODA_STRUCTURED_RESULT_SCHEMA_VERSION: &str = "hartevo.coda-structured-result/v1";
pub const CODA_STRUCTURED_RESULT_CONTRACT_VERSION: &str = "EXT-CODA-01-L1/v1";
pub const CODA_STRUCTURED_RESULT_PLUGIN_ID: &str = "coda-structured-result";
pub const CODA_STRUCTURED_RESULT_PLUGIN_VERSION: &str = "0.1.0";
pub const CODA_SERVICE_ID: &str = "coda.structured-result";
pub const CODA_PROVIDER_ID: &str = "coda.structured-result.metadata";
pub const CODA_PROVIDER_REVISION: &str = "coda-api-v1-metadata-read-r1";
pub const CODA_CONSUMER_ID: &str = "mission.coda.structured-result";
pub const CODA_API_REFERENCE_URL: &str = "https://coda.io/developers/apis/v1";
pub const CODA_API_BASE_URL: &str = "https://coda.io/apis/v1";
pub const CODA_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const CODA_STRUCTURED_RESULT_CONTRACT_PATH: &str =
    "contracts/plugins/coda-structured-result/coda-structured-result.v1.json";
pub const CODA_STRUCTURED_RESULT_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/coda-structured-result/coda-structured-result.v1.json"
);

#[must_use]
pub fn contract_digest() -> Digest {
    sha256_digest(CODA_STRUCTURED_RESULT_CONTRACT_JSON.as_bytes())
}

#[must_use]
pub fn plugin_version_digest() -> Digest {
    sha256_digest(CODA_STRUCTURED_RESULT_PLUGIN_VERSION.as_bytes())
}

/// Layer 1 deliberately reports no native, connected, first-party, durable,
/// kernel, or external-write authority.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
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
    pub const fn external_writes() -> bool {
        false
    }

    #[must_use]
    pub const fn formula_execution() -> bool {
        false
    }

    #[must_use]
    pub const fn generic_knowledge_registry() -> bool {
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
}

/// Machine-readable checked-in contract with a small semantic validator. The
/// JSON remains the source of truth for the external contract boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodaStructuredResultContract {
    value: serde_json::Value,
}

impl CodaStructuredResultContract {
    pub fn baseline() -> Result<Self, CodaStructuredResultError> {
        let value = serde_json::from_str(CODA_STRUCTURED_RESULT_CONTRACT_JSON)
            .map_err(|error| CodaStructuredResultError::Contract(error.to_string()))?;
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

    pub fn validate(&self) -> Result<(), CodaStructuredResultError> {
        let object = self.value.as_object().ok_or_else(|| {
            CodaStructuredResultError::Contract("contract is not an object".to_owned())
        })?;
        for key in [
            "schemaVersion",
            "contractVersion",
            "pluginVersion",
            "layer",
            "authority",
            "typedSurface",
            "api",
            "scope",
            "bounds",
            "pagination",
            "evidence",
            "redaction",
            "registration",
            "transports",
            "forbidden",
            "layer2Gaps",
            "honesty",
        ] {
            if !object.contains_key(key) {
                return Err(CodaStructuredResultError::Contract(format!(
                    "missing top-level field {key}"
                )));
            }
        }
        if object
            .get("schemaVersion")
            .and_then(serde_json::Value::as_str)
            != Some(CODA_STRUCTURED_RESULT_SCHEMA_VERSION)
            || object
                .get("contractVersion")
                .and_then(serde_json::Value::as_str)
                != Some(CODA_STRUCTURED_RESULT_CONTRACT_VERSION)
            || object
                .get("pluginVersion")
                .and_then(serde_json::Value::as_str)
                != Some(CODA_STRUCTURED_RESULT_PLUGIN_VERSION)
            || object.get("layer") != Some(&serde_json::Value::from(1))
        {
            return Err(CodaStructuredResultError::Contract(
                "contract identity drifted".to_owned(),
            ));
        }
        let authority = object
            .get("authority")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| CodaStructuredResultError::Contract("authority missing".to_owned()))?;
        for key in [
            "connected",
            "native",
            "firstParty",
            "externalWrites",
            "rowWrites",
            "pageWrites",
            "buttonWrites",
            "formulaExecution",
            "genericKnowledgeRegistry",
            "kernelAuthority",
            "outcomeAuthority",
        ] {
            if authority.get(key) != Some(&serde_json::Value::Bool(false)) {
                return Err(CodaStructuredResultError::Contract(format!(
                    "authority.{key} must be false"
                )));
            }
        }
        let api = object
            .get("api")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| CodaStructuredResultError::Contract("api missing".to_owned()))?;
        if api.get("reference").and_then(serde_json::Value::as_str) != Some(CODA_API_REFERENCE_URL)
            || api.get("baseUrl").and_then(serde_json::Value::as_str) != Some(CODA_API_BASE_URL)
            || api.get("version").and_then(serde_json::Value::as_str) != Some("v1")
            || api.get("writes") != Some(&serde_json::Value::Array(Vec::new()))
        {
            return Err(CodaStructuredResultError::Contract(
                "Coda API boundary drifted".to_owned(),
            ));
        }
        let transports = object
            .get("transports")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| CodaStructuredResultError::Contract("transports missing".to_owned()))?;
        for name in ["fixture", "recording", "fake", "loopback", "BLOCKED_ENV"] {
            let transport = transports
                .get(name)
                .and_then(serde_json::Value::as_object)
                .ok_or_else(|| {
                    CodaStructuredResultError::Contract(format!("transport {name} missing"))
                })?;
            for field in ["connected", "native", "firstParty"] {
                if transport.get(field) != Some(&serde_json::Value::Bool(false)) {
                    return Err(CodaStructuredResultError::Contract(format!(
                        "transport {name}.{field} must be false"
                    )));
                }
            }
        }
        Ok(())
    }
}

pub type CodaContract = CodaStructuredResultContract;
pub type CodaScope = CodaStructuredResultScope;
pub type CodaEvidence = CodaStructuredResultEvidence;
pub type CodaProposal = CodaStructuredResultProposal;
pub type CodaRegistrationRevocationReceipt = CodaRegistrationRevocation;

#[cfg(test)]
mod contract_tests {
    use super::{
        CODA_API_BASE_URL, CODA_API_REFERENCE_URL, CODA_STRUCTURED_RESULT_CONTRACT_VERSION,
        CODA_STRUCTURED_RESULT_SCHEMA_VERSION, CodaStructuredResultContract, Layer1Authority,
        contract_digest,
    };

    #[test]
    fn contract_is_machine_readable_and_layer_one_honest() {
        let contract = CodaStructuredResultContract::baseline().expect("valid Coda contract");
        let value = contract.value();
        assert_eq!(
            value["schemaVersion"],
            CODA_STRUCTURED_RESULT_SCHEMA_VERSION
        );
        assert_eq!(
            value["contractVersion"],
            CODA_STRUCTURED_RESULT_CONTRACT_VERSION
        );
        assert_eq!(value["api"]["reference"], CODA_API_REFERENCE_URL);
        assert_eq!(value["api"]["baseUrl"], CODA_API_BASE_URL);
        assert_eq!(value["layer"], 1);
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::external_writes());
        assert_eq!(contract.digest(), contract_digest());
    }
}
