//! Standalone Layer-1 Fastly service-result plugin.
//!
//! The crate exposes typed, bounded Fastly service/version/environment/domain/
//! validation evidence for a Mission. It is deliberately read/proposal/
//! recording-only: it has no native credential resolver, native HTTPS client,
//! deployment mutation, raw VCL/config surface, durable provider receipt, or
//! Hartevo kernel authority.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

use serde_json::Value;
use thiserror::Error;

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;
pub mod transport;

pub use consumer::{FastlyServiceConsumer, MissionFastlyConsumer, MissionFastlyServiceConsumer};
pub use error::{FastlyError, FastlyServiceResultError, Result};
pub use model::*;
pub use provider::{
    FastlyProvider, FastlyReadRequest, FastlyServiceResultRegistration, Registration,
    RegistrationState, RegistrationTransition,
};
pub use service::{
    FastlyService, FastlyServiceDefinition, FastlyServiceResultCapability,
    FastlyServiceResultOperation, FastlyServiceResultService, FastlyServiceResultServiceDefinition,
    FastlyServiceResultServiceError,
};
pub use transport::{
    BlockedEnvFastlyTransport, BlockedEnvTransport, FakeFastlyTransport, FakeTransport,
    FastlyDomainPagePayload, FastlyEndpoint, FastlyEnvironmentPayload, FastlyFixtureSet,
    FastlyFixtureTransport, FastlyHttpMethod, FastlyRequest, FastlyResponse, FastlyResponseBody,
    FastlyResponseError, FastlyServicePayload, FastlyTransport, FastlyTransportError,
    FastlyValidationPayload, FastlyVersionPayload, FixtureTransport, LoopbackFastlyTransport,
    LoopbackTransport, RecordingFastlyTransport, RecordingTransport, TransportProvenance,
};

pub const FASTLY_SERVICE_RESULT_SCHEMA_VERSION: &str = "hartevo.fastly-service-result/v1";
pub const FASTLY_SERVICE_RESULT_CONTRACT_VERSION: &str = "EXT-FASTLY-01-L1/v1";
pub const FASTLY_SERVICE_RESULT_PLUGIN_VERSION: &str = "0.1.0";
pub const FASTLY_SERVICE_RESULT_PLUGIN_ID: &str = "fastly.service-result";
pub const FASTLY_SERVICE_RESULT_CONTRACT_PATH: &str =
    "contracts/plugins/fastly-service-result/fastly-service-result.v1.json";
pub const FASTLY_SERVICE_RESULT_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/fastly-service-result/fastly-service-result.v1.json");
pub const FASTLY_SERVICE_RESULT_SERVICE_ID: &str = "fastly.service-result.read";
pub const FASTLY_SERVICE_RESULT_SERVICE_NAME: &str = "FastlyServiceResultService";
pub const FASTLY_SERVICE_RESULT_PROVIDER_ID: &str = "fastly.fastly-service-result.read";
pub const FASTLY_SERVICE_RESULT_PROVIDER_NAME: &str = "FastlyProvider";
pub const FASTLY_SERVICE_RESULT_CONSUMER_ID: &str = "mission.fastly-service-result";
pub const FASTLY_SERVICE_RESULT_CONSUMER_NAME: &str = "MissionFastlyServiceConsumer";
pub const FASTLY_SERVICE_RESULT_SERVICE_SCHEMA: &str = "hartevo.fastly-service-result-service/v1";
pub const FASTLY_SERVICE_RESULT_PROVIDER_SCHEMA: &str = "hartevo.fastly-provider/v1";
pub const FASTLY_SERVICE_RESULT_CONSUMER_SCHEMA: &str =
    "hartevo.mission-fastly-service-consumer/v1";
pub const FASTLY_API_ORIGIN: &str = "https://api.fastly.com";
pub const FASTLY_OFFICIAL_API: &str = "https://www.fastly.com/documentation/reference/api/";
pub const API_REVISION: &str = "fastly-service-version-environment-domain-validation-get-v1";
pub const FASTLY_API_REVISION: &str = API_REVISION;
pub const CONTRACT_VERSION: &str = FASTLY_SERVICE_RESULT_CONTRACT_VERSION;
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.fastly-service-result/v1|layer=1|service=fastly.service-result.read|provider=fastly.fastly-service-result.read|consumer=mission.fastly-service-result|api=fastly-service-version-environment-domain-validation-get-v1";
pub const CONTRACT_DIGEST: &str =
    "d18d3b07ee3c5e6ffaecf9d50968efae24fe85089d6624896419337ef244dcc7";
pub const FASTLY_BLOCKED_ENV: &str = "BLOCKED_ENV";

#[must_use]
pub fn contract_digest() -> Digest {
    Digest::from_text(CONTRACT_DIGEST_INPUT)
}

#[must_use]
pub fn contract_digest_string() -> &'static str {
    CONTRACT_DIGEST
}

#[must_use]
pub fn plugin_version_digest() -> Digest {
    Digest::from_text(FASTLY_SERVICE_RESULT_PLUGIN_VERSION)
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ContractError {
    #[error("Fastly service-result contract JSON is invalid: {0}")]
    Json(String),
    #[error("Fastly service-result contract does not match the typed Layer-1 boundary")]
    Drift,
}

#[derive(Clone, Debug)]
pub struct FastlyServiceResultContract {
    document: Value,
}

impl FastlyServiceResultContract {
    pub fn baseline() -> std::result::Result<Self, ContractError> {
        let document = serde_json::from_str::<Value>(FASTLY_SERVICE_RESULT_CONTRACT_JSON)
            .map_err(|error| ContractError::Json(error.to_string()))?;
        let contract = Self { document };
        contract.validate()?;
        Ok(contract)
    }

    #[must_use]
    pub fn document(&self) -> &Value {
        &self.document
    }

    #[must_use]
    pub fn value(&self) -> &Value {
        &self.document
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        contract_digest()
    }

    pub fn validate(&self) -> std::result::Result<(), ContractError> {
        let get = |path: &[&str]| -> Option<&Value> {
            path.iter()
                .try_fold(&self.document, |value, key| value.get(*key))
        };
        let states = get(&["states"]).and_then(Value::as_array);
        let provenance = get(&["provider", "transportProvenance"]).and_then(Value::as_array);
        let writes = get(&["allowlist", "writes"]).and_then(Value::as_array);
        let exact_states = [
            "present",
            "empty",
            "partial",
            "access_loss",
            "provider_unknown",
            "tampered",
            "stale",
            "revoked",
        ];
        let required_paths = [
            "GET /service/{service}",
            "GET /service/{service}/version/{version}",
            "GET /service/{service}/version/{version}/environment/{environment}",
            "GET /service/{service}/version/{version}/domain/{domain}",
            "GET /service/{service}/version/{version}/validation",
        ];
        let valid_states = states.is_some_and(|values| {
            exact_states
                .iter()
                .all(|state| values.iter().any(|value| value == state))
        });
        let valid_provenance = provenance.is_some_and(|values| {
            ["fixture", "recording", "fake", "loopback", "BLOCKED_ENV"]
                .iter()
                .all(|name| values.iter().any(|value| value == name))
        });
        let valid_paths = get(&["provider", "allowlistedGetPaths"])
            .and_then(Value::as_array)
            .is_some_and(|values| {
                required_paths
                    .iter()
                    .all(|path| values.iter().any(|value| value == path))
            });
        let authority_false = [
            ["authority", "connected"],
            ["authority", "native"],
            ["authority", "firstParty"],
            ["authority", "externalWrites"],
            ["authority", "kernelAuthority"],
            ["authority", "outcomeAuthority"],
            ["provider", "connectedEvidence"],
            ["provider", "nativeEvidence"],
            ["provider", "firstPartyEvidence"],
            ["provider", "durableProviderReceipt"],
            ["provider", "externalWrites"],
        ]
        .iter()
        .all(|path| get(path) == Some(&Value::Bool(false)));
        if get(&["schemaVersion"])
            != Some(&Value::String(
                FASTLY_SERVICE_RESULT_SCHEMA_VERSION.to_owned(),
            ))
            || get(&["contractVersion"])
                != Some(&Value::String(
                    FASTLY_SERVICE_RESULT_CONTRACT_VERSION.to_owned(),
                ))
            || get(&["pluginVersion"])
                != Some(&Value::String(
                    FASTLY_SERVICE_RESULT_PLUGIN_VERSION.to_owned(),
                ))
            || get(&["pluginId"])
                != Some(&Value::String(FASTLY_SERVICE_RESULT_PLUGIN_ID.to_owned()))
            || get(&["layer"]) != Some(&Value::from(1))
            || get(&["digestInput"]) != Some(&Value::String(CONTRACT_DIGEST_INPUT.to_owned()))
            || get(&["contractDigest"]) != Some(&Value::String(CONTRACT_DIGEST.to_owned()))
            || get(&["officialApi"]) != Some(&Value::String(FASTLY_OFFICIAL_API.to_owned()))
            || get(&["service", "id"])
                != Some(&Value::String(FASTLY_SERVICE_RESULT_SERVICE_ID.to_owned()))
            || get(&["provider", "id"])
                != Some(&Value::String(FASTLY_SERVICE_RESULT_PROVIDER_ID.to_owned()))
            || get(&["consumer", "id"])
                != Some(&Value::String(FASTLY_SERVICE_RESULT_CONSUMER_ID.to_owned()))
            || !valid_states
            || !valid_provenance
            || !valid_paths
            || writes.is_none_or(|items| !items.is_empty())
            || !authority_false
        {
            return Err(ContractError::Drift);
        }
        Ok(())
    }
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
    pub const fn native_provider() -> bool {
        false
    }

    #[must_use]
    pub const fn first_party() -> bool {
        false
    }

    #[must_use]
    pub const fn first_party_provider() -> bool {
        false
    }

    #[must_use]
    pub const fn external_writes() -> bool {
        false
    }

    #[must_use]
    pub const fn durable_provider_receipt() -> bool {
        false
    }

    #[must_use]
    pub const fn independent_native_readback() -> bool {
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
    pub const fn work_product_adoption() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn checked_contract_is_versioned_bounded_and_layer_one_honest() {
        let contract = FastlyServiceResultContract::baseline().expect("Fastly contract");
        assert_eq!(
            contract.value()["schemaVersion"],
            FASTLY_SERVICE_RESULT_SCHEMA_VERSION
        );
        assert_eq!(
            contract.value()["contractVersion"],
            FASTLY_SERVICE_RESULT_CONTRACT_VERSION
        );
        assert_eq!(contract.value()["contractDigest"], CONTRACT_DIGEST);
        assert_eq!(contract_digest(), CONTRACT_DIGEST);
        assert_eq!(
            contract.value()["typedSurface"]["service"],
            FASTLY_SERVICE_RESULT_SERVICE_NAME
        );
        assert_eq!(
            contract.value()["typedSurface"]["provider"],
            FASTLY_SERVICE_RESULT_PROVIDER_NAME
        );
        assert_eq!(
            contract.value()["typedSurface"]["consumer"],
            FASTLY_SERVICE_RESULT_CONSUMER_NAME
        );
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::external_writes());
        assert!(!Layer1Authority::durable_provider_receipt());
        assert!(!Layer1Authority::kernel_authority());
        assert!(!Layer1Authority::outcome_authority());
        assert!(!Layer1Authority::work_product_adoption());
    }
}
