//! Standalone Layer-1 governed Fly.io deployment-result boundary.
//!
//! This crate models only bounded, GET-shaped Apps and Machines evidence,
//! digest fences, reversible/revocable registration, redacted receipts, and a
//! Mission-scoped review/record seam. It does not own Hartevo Truth, Consent,
//! Effect, Receipt, Verification, Outcome, or Work Product authority. Native
//! Fly token resolution and HTTPS remain an explicit Layer-2 gap.

#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::missing_fields_in_debug,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::fn_params_excessive_bools,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps,
    missing_debug_implementations
)]

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    MissionFlyioDeploymentConsumer, MissionFlyioDeploymentResult, ProposalDisposition,
    RecordedFlyioDeploymentResult,
};
pub use error::{FlyioDeploymentResultError, FlyioTransportError, Result};
pub use model::*;
pub use provider::{
    AppPage, BlockedEnvTransport, Cursor, FixtureResponse, FixtureTransport, FlyioMachinesProvider,
    FlyioMachinesProviderDefinition, FlyioOperation, FlyioTransport, GetAppRequest,
    GetMachineRequest, ListAppsRequest, ListMachinesRequest, LoopbackTransport, MachinePage,
    RecordedRequest, RecordingTransport, TransportResponse,
};
pub use service::{
    CapabilityDescription, FlyioDeploymentResultProposal, FlyioDeploymentResultRegistration,
    FlyioDeploymentResultService, FlyioEvidenceRequest, RegistrationStatus,
    RegistrationTransitionEvidence, VerificationFailure, VerificationReport,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.flyio-deployment-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-FLYIO-01-L1/v1";
pub const PLUGIN_ID: &str = "flyio.deployment.result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "flyio.deployment.result.read";
pub const PROVIDER_ID: &str = "flyio.machines.provider";
pub const API_REVISION: &str = "fly-machines-apps-get-app-list-machines-get-machine-2026-08-r1";
pub const CONSUMER_ID: &str = "mission.flyio-deployment-result.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.flyio-deployment-result/v1|layer=1|service=flyio.deployment.result.read|provider=flyio.machines.provider|consumer=mission.flyio-deployment-result.consumer|api=fly-machines-apps-get-app-list-machines-get-machine-2026-08-r1";
pub const CONTRACT_DIGEST: &str =
    "cf78d4cd55c45adb0dcef5b8ae749756b079a3c34653123f29525e9cd2c21a53";
pub const LAYER1_PERMISSIONS: [&str; 4] = [
    "fly.apps.read",
    "fly.machines.read",
    "fly.releases.read",
    "mission.scope",
];
pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_PAGE_SIZE: u16 = 50;
pub const MAX_PAGES: u16 = 8;
pub const MAX_MACHINE_CARDINALITY: usize = 64;
pub const MAX_RECENT_EVENTS: usize = 16;
pub const MAX_SERVICE_PORTS: usize = 16;
pub const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/flyio-deployment-result/flyio-deployment-result.v1.json"
);

pub fn contract_digest() -> Digest {
    Digest::from_text(CONTRACT_DIGEST_INPUT)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlyioDeploymentResultContract {
    value: serde_json::Value,
}

impl FlyioDeploymentResultContract {
    pub fn baseline() -> Result<Self> {
        let value = serde_json::from_str::<serde_json::Value>(CONTRACT_JSON)
            .map_err(|_| FlyioDeploymentResultError::ContractDrift)?;
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

    pub fn validate(&self) -> Result<()> {
        let object = self
            .value
            .as_object()
            .ok_or(FlyioDeploymentResultError::ContractDrift)?;
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
            "service",
            "provider",
            "consumer",
            "credentials",
            "scope",
            "registration",
            "pagination",
            "projection",
            "receipts",
            "evidence",
            "provenance",
            "authorityBoundary",
            "forbiddenEffects",
            "layer2Gaps",
        ] {
            if !object.contains_key(key) {
                return Err(FlyioDeploymentResultError::ContractDrift);
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
            || contract_digest().as_str() != CONTRACT_DIGEST
        {
            return Err(FlyioDeploymentResultError::ContractDrift);
        }
        let service = object
            .get("service")
            .and_then(serde_json::Value::as_object)
            .ok_or(FlyioDeploymentResultError::ContractDrift)?;
        if service.get("id").and_then(serde_json::Value::as_str) != Some(SERVICE_ID)
            || service.get("readOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("proposalOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("externalWrites") != Some(&serde_json::Value::Bool(false))
            || service.get("kernelAuthority") != Some(&serde_json::Value::Bool(false))
        {
            return Err(FlyioDeploymentResultError::ContractDrift);
        }
        let provider = object
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .ok_or(FlyioDeploymentResultError::ContractDrift)?;
        if provider.get("id").and_then(serde_json::Value::as_str) != Some(PROVIDER_ID)
            || provider
                .get("apiRevision")
                .and_then(serde_json::Value::as_str)
                != Some(API_REVISION)
            || provider.get("connected") != Some(&serde_json::Value::Bool(false))
            || provider.get("native") != Some(&serde_json::Value::Bool(false))
            || provider.get("firstParty") != Some(&serde_json::Value::Bool(false))
            || provider.get("externalWrites") != Some(&serde_json::Value::Bool(false))
        {
            return Err(FlyioDeploymentResultError::ContractDrift);
        }
        let consumer = object
            .get("consumer")
            .and_then(serde_json::Value::as_object)
            .ok_or(FlyioDeploymentResultError::ContractDrift)?;
        if consumer.get("id").and_then(serde_json::Value::as_str) != Some(CONSUMER_ID)
            || consumer.get("adoptsOutcome") != Some(&serde_json::Value::Bool(false))
            || consumer.get("adoptsWorkProduct") != Some(&serde_json::Value::Bool(false))
        {
            return Err(FlyioDeploymentResultError::ContractDrift);
        }
        let provenance = object
            .get("provenance")
            .and_then(serde_json::Value::as_object)
            .ok_or(FlyioDeploymentResultError::ContractDrift)?;
        if provenance.get("connected") != Some(&serde_json::Value::Bool(false))
            || provenance.get("native") != Some(&serde_json::Value::Bool(false))
            || provenance.get("firstParty") != Some(&serde_json::Value::Bool(false))
            || provenance.get("providerReceipt") != Some(&serde_json::Value::Bool(false))
        {
            return Err(FlyioDeploymentResultError::ContractDrift);
        }
        for forbidden in [
            "CreateApp",
            "DeleteApp",
            "CreateMachine",
            "StartMachine",
            "StopMachine",
            "UpdateMachine",
            "SuspendMachine",
            "CordonMachine",
            "LeaseMachine",
            "DeleteMachine",
            "ReadLogs",
            "ReadFilesystem",
            "ExportNetwork",
            "ExportEnvironment",
            "ExportRawConfig",
        ] {
            if !object
                .get("forbiddenEffects")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(forbidden)))
            {
                return Err(FlyioDeploymentResultError::ContractDrift);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    pub const fn connected() -> bool {
        false
    }

    pub const fn native() -> bool {
        false
    }

    pub const fn first_party() -> bool {
        false
    }

    pub const fn provider_receipt() -> bool {
        false
    }

    pub const fn outcome_adopted() -> bool {
        false
    }

    pub const fn work_product_adopted() -> bool {
        false
    }
}
