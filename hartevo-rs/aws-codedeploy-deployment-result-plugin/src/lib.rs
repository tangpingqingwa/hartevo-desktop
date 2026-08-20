//! Standalone Layer-1 AWS CodeDeploy deployment-result capability.
//!
//! The crate exposes typed account/region/application/deployment-group/
//! deployment/revision/target lifecycle evidence, a provider seam, a Mission
//! proposal consumer, and bounded redacted recording. It has no deployment
//! effect authority and imports no Hartevo application, desktop, domain,
//! storage, catalog, connector, keyring, or kernel authority.

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

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;
pub mod transport;

pub use consumer::{
    MissionAwsCodeDeployConsumer, MissionAwsCodeDeployDeploymentConsumer,
    MissionAwsCodeDeployDeploymentResult,
};
pub use error::{
    AwsCodeDeployDeploymentResultError, AwsCodeDeployError, AwsCodeDeployTransportError,
    CodeDeployDeploymentResultError, CodeDeployTransportError,
};
pub use model::*;
pub use provider::*;
pub use service::*;
pub use transport::*;

pub const SCHEMA_VERSION: &str = "hartevo.aws-codedeploy-deployment-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-AWSCODEDEPLOY-01-L1/v1";
pub const PLUGIN_ID: &str = "hartevo.aws-codedeploy-deployment-result";
pub const PLUGIN_VERSION: PluginVersion = PluginVersion::new(1, 0, 0);
pub const PROVIDER_ID: &str = "aws.codedeploy.deployment-result.recording";
pub const PROVIDER_VERSION: PluginVersion = PluginVersion::new(1, 0, 0);
pub const SERVICE_ID: &str = "aws.codedeploy.deployment-result.read";
pub const CONSUMER_ID: &str = "mission.aws-codedeploy-deployment-result.consumer";
pub const API_REVISION: &str =
    "codedeploy-list-deployments-get-deployment-list-deployment-targets-r1";
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const LAYER: u8 = 1;
pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/aws-codedeploy-deployment-result/aws-codedeploy-deployment-result.v1.json"
);

pub const AWS_CODEDEPLOY_SCHEMA_VERSION: &str = SCHEMA_VERSION;
pub const AWS_CODEDEPLOY_CONTRACT_VERSION: &str = CONTRACT_VERSION;
pub const AWS_CODEDEPLOY_PLUGIN_ID: &str = PLUGIN_ID;
pub const AWS_CODEDEPLOY_PROVIDER_ID: &str = PROVIDER_ID;
pub const AWS_CODEDEPLOY_SERVICE_ID: &str = SERVICE_ID;
pub const AWS_CODEDEPLOY_CONSUMER_ID: &str = CONSUMER_ID;
pub const AWS_CODEDEPLOY_API_REVISION: &str = API_REVISION;

/// Native SigV4 resolution, live CodeDeploy HTTPS, durable provider receipts,
/// independent readback, consented deployment effects, and verified Mission or
/// Outcome adoption are Layer-2 exits. Layer-1 fixtures, recordings, loopback,
/// and BLOCKED_ENV are never Connected or native.
pub const NATIVE_GAP: &str = "BLOCKED_ENV: native SigV4 credential resolution, live AWS CodeDeploy HTTPS reads, durable provider receipts, independent readback, consented deployment effects, and verified Mission/Outcome adoption remain Layer-2 work";

pub fn canonical_digest<T: serde::Serialize + ?Sized>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("typed contract values serialize");
    Digest::from_bytes(&bytes)
}

pub fn contract_digest() -> Digest {
    Digest::from_bytes(CONTRACT_JSON.as_bytes())
}

pub fn provider_digest() -> Digest {
    Digest::from_serializable(&(PROVIDER_ID, PROVIDER_VERSION, API_REVISION))
}

pub fn api_digest() -> Digest {
    Digest::from_text(API_REVISION)
}

pub fn evidence_contract_digest(scope: &CodeDeployScope) -> Digest {
    Digest::from_serializable(&(
        "aws-codedeploy-evidence/v1",
        &scope.permissions.digest(),
        &scope.digest(),
        API_REVISION,
    ))
}

/// The Layer-1 contract is checked in and checked again by the typed crate so
/// a drifted JSON document cannot silently alter the service boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsCodeDeployDeploymentResultContract {
    value: serde_json::Value,
}

impl AwsCodeDeployDeploymentResultContract {
    pub fn baseline() -> Result<Self, AwsCodeDeployDeploymentResultError> {
        let value = serde_json::from_str(CONTRACT_JSON)
            .map_err(|_| AwsCodeDeployDeploymentResultError::ContractInvalid("invalid JSON"))?;
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

    pub fn validate(&self) -> Result<(), AwsCodeDeployDeploymentResultError> {
        let object =
            self.value
                .as_object()
                .ok_or(AwsCodeDeployDeploymentResultError::ContractInvalid(
                    "contract root is not an object",
                ))?;
        for key in [
            "schemaVersion",
            "contractVersion",
            "layer",
            "plugin",
            "service",
            "provider",
            "scope",
            "evidence",
            "registration",
            "provenance",
            "forbidden",
            "honesty",
            "nativeGaps",
        ] {
            if !object.contains_key(key) {
                return Err(AwsCodeDeployDeploymentResultError::ContractInvalid(
                    "required contract key is missing",
                ));
            }
        }
        if object
            .get("schemaVersion")
            .and_then(serde_json::Value::as_str)
            != Some(SCHEMA_VERSION)
            || object
                .get("contractVersion")
                .and_then(serde_json::Value::as_str)
                != Some(CONTRACT_VERSION)
            || object.get("layer").and_then(serde_json::Value::as_u64) != Some(u64::from(LAYER))
        {
            return Err(AwsCodeDeployDeploymentResultError::ContractInvalid(
                "contract identity drifted",
            ));
        }
        let plugin = object
            .get("plugin")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsCodeDeployDeploymentResultError::ContractInvalid(
                "plugin is not an object",
            ))?;
        if plugin.get("id").and_then(serde_json::Value::as_str) != Some(PLUGIN_ID)
            || plugin.get("version").and_then(serde_json::Value::as_str) != Some("1.0.0")
            || plugin.get("reversibleRegistration") != Some(&serde_json::Value::Bool(true))
            || plugin.get("revocableRegistration") != Some(&serde_json::Value::Bool(true))
        {
            return Err(AwsCodeDeployDeploymentResultError::ContractInvalid(
                "plugin boundary drifted",
            ));
        }
        let service = object
            .get("service")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsCodeDeployDeploymentResultError::ContractInvalid(
                "service is not an object",
            ))?;
        if service.get("id").and_then(serde_json::Value::as_str) != Some(SERVICE_ID)
            || service.get("readOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("proposalOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("recordingOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("externalWrites") != Some(&serde_json::Value::Bool(false))
            || service.get("kernelAuthority") != Some(&serde_json::Value::Bool(false))
            || service.get("outcomeAdoption") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsCodeDeployDeploymentResultError::ContractInvalid(
                "service authority widened",
            ));
        }
        let provider = object
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsCodeDeployDeploymentResultError::ContractInvalid(
                "provider is not an object",
            ))?;
        if provider.get("id").and_then(serde_json::Value::as_str) != Some(PROVIDER_ID)
            || provider.get("connectedEvidence") != Some(&serde_json::Value::Bool(false))
            || provider.get("nativeEvidence") != Some(&serde_json::Value::Bool(false))
            || provider
                .get("authentication")
                .and_then(serde_json::Value::as_object)
                .and_then(|auth| auth.get("rawCredentialMaterial"))
                != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsCodeDeployDeploymentResultError::ContractInvalid(
                "provider authority widened",
            ));
        }
        let provenance = object
            .get("provenance")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsCodeDeployDeploymentResultError::ContractInvalid(
                "provenance is not an object",
            ))?;
        if provenance.get("connected") != Some(&serde_json::Value::Bool(false))
            || provenance.get("native") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsCodeDeployDeploymentResultError::ContractInvalid(
                "provenance claims widened",
            ));
        }
        let forbidden = object
            .get("forbidden")
            .and_then(serde_json::Value::as_array)
            .ok_or(AwsCodeDeployDeploymentResultError::ContractInvalid(
                "forbidden list is not an array",
            ))?;
        for required in [
            "deployment_create",
            "deployment_stop",
            "deployment_mutation",
            "log_export",
            "script_export",
            "artifact_bytes",
            "serialize_secret_material",
            "kernel_outcome",
            "outcome_adoption",
        ] {
            if !forbidden
                .iter()
                .any(|value| value.as_str() == Some(required))
            {
                return Err(AwsCodeDeployDeploymentResultError::ContractInvalid(
                    "forbidden authority missing",
                ));
            }
        }
        Ok(())
    }
}

pub fn validate_contract() -> Result<(), AwsCodeDeployDeploymentResultError> {
    AwsCodeDeployDeploymentResultContract::baseline().map(|_| ())
}

/// Compile-time/read-only authority marker used by audits and adversarial
/// tests. All authority flags are deliberately false.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReadOnlyAuthority;

impl ReadOnlyAuthority {
    pub const fn store() -> bool {
        false
    }

    pub const fn keyring() -> bool {
        false
    }

    pub const fn deployment_effect() -> bool {
        false
    }

    pub const fn external_writes() -> bool {
        false
    }

    pub const fn raw_logs() -> bool {
        false
    }

    pub const fn raw_scripts() -> bool {
        false
    }

    pub const fn artifact_bytes() -> bool {
        false
    }

    pub const fn kernel_authority() -> bool {
        false
    }

    pub const fn native_connected() -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    #[test]
    fn checked_in_contract_is_layer_one_and_native_honest() {
        validate_contract().expect("contract validates");
        let document: Value = serde_json::from_str(CONTRACT_JSON).expect("contract JSON");
        assert_eq!(document["schemaVersion"], SCHEMA_VERSION);
        assert_eq!(document["contractVersion"], CONTRACT_VERSION);
        assert_eq!(document["layer"], LAYER);
        assert_eq!(document["service"]["externalWrites"], false);
        assert_eq!(document["provider"]["connectedEvidence"], false);
        assert_eq!(document["provider"]["nativeEvidence"], false);
        assert_eq!(document["honesty"]["nativeStatus"], BLOCKED_ENV);
        assert!(!ReadOnlyAuthority::deployment_effect());
        assert!(!ReadOnlyAuthority::raw_logs());
        assert!(!ReadOnlyAuthority::raw_scripts());
        assert!(!ReadOnlyAuthority::artifact_bytes());
        assert_eq!(contract_digest().as_str().len(), 71);
    }
}
