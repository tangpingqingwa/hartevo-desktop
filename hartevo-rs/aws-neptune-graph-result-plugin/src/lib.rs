//! Standalone Layer-1 governed Amazon Neptune graph-query result boundary.
//!
//! The crate deliberately stops at read, proposal, recording, and verification
//! seams.  It does not resolve credentials, sign an AWS request, connect to a
//! VPC endpoint, become kernel Truth/Consent/Effect/Receipt authority, or adopt
//! an Outcome or Work Product.  Every available transport is consequently
//! non-connected, non-native, and non-first-party.

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

use sha2::{Digest as ShaDigest, Sha256};

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod query;
pub mod service;

pub use consumer::{
    MissionAwsNeptuneConsumer, MissionAwsNeptuneConsumerError, MissionAwsNeptuneResult,
    RecordedAwsNeptuneResult,
};
pub use error::{AwsNeptuneGraphResultError, AwsNeptuneTransportError, Result};
pub use model::*;
pub use provider::{
    AwsNeptuneOperation, AwsNeptuneProvider, AwsNeptuneProviderDefinition, AwsNeptuneTransport,
    BlockedEnvTransport, ExecuteOpenCypherQueryRequest, ExecuteOpenCypherQueryResponse,
    FixtureTransport, LoopbackTransport, OpaqueCursor, RecordedRequest, RecordingTransport,
};
pub use query::{
    Direction, GraphProjection, NodePattern, OpenCypherAst, OpenCypherQuery,
    OpenCypherQueryTemplate, ParameterizedOpenCypher, QueryCompileError, QueryParameter,
    QueryParameterType, RelationshipPattern,
};
pub use service::{
    AwsNeptuneCapabilities, AwsNeptuneGraphResultProposal, AwsNeptuneGraphResultRegistration,
    AwsNeptuneGraphResultService, FailureEvidence, GraphQueryProposalRequest, RegistrationState,
    RegistrationTransitionEvidence, VerificationReport,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.aws-neptune-graph-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-AWS-NEPTUNE-01-L1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.aws-neptune-graph-result/v1|layer=1|service=aws.neptune.graph.result.read|provider=aws.neptune.graph.result.recording|consumer=mission.aws-neptune-graph-result.consumer|api=neptune-execute-open-cypher-query-2022-11-30-r1";
pub const CONTRACT_DIGEST: &str =
    "723c20505fe006f776ba4fa771ff00ff792abdb90f77abe49f7e4087daca4bd2";
pub const PLUGIN_ID: &str = "aws.neptune.graph.result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "aws.neptune.graph.result.read";
pub const PROVIDER_ID: &str = "aws.neptune.graph.result.recording";
pub const CONSUMER_ID: &str = "mission.aws-neptune-graph-result.consumer";
pub const API_REVISION: &str = "neptune-execute-open-cypher-query-2022-11-30-r1";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const LAYER1_PERMISSIONS: [&str; 2] = ["neptune-db:ExecuteOpenCypherQuery", "mission.scope"];
pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/aws-neptune-graph-result/aws-neptune-graph-result.v1.json"
);

/// SHA-256 of the stable contract digest input.
pub fn contract_digest() -> String {
    hex::encode(Sha256::digest(CONTRACT_DIGEST_INPUT.as_bytes()))
}

/// Parsed and pinned versioned contract metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsNeptuneGraphResultContract {
    value: serde_json::Value,
}

impl AwsNeptuneGraphResultContract {
    /// Load and validate the checked-in contract document.
    pub fn baseline() -> Result<Self> {
        let value = serde_json::from_str::<serde_json::Value>(CONTRACT_JSON)
            .map_err(|_| error::AwsNeptuneGraphResultError::ContractDrift)?;
        let contract = Self { value };
        contract.validate()?;
        Ok(contract)
    }

    /// Access the validated JSON document.
    pub const fn value(&self) -> &serde_json::Value {
        &self.value
    }

    /// Return the contract digest represented by the pinned digest input.
    pub fn digest(&self) -> Digest {
        Digest::from_text(CONTRACT_DIGEST_INPUT)
    }

    /// Validate metadata and the honest Layer-1 authority boundary.
    pub fn validate(&self) -> Result<()> {
        let object = self
            .value
            .as_object()
            .ok_or(error::AwsNeptuneGraphResultError::ContractDrift)?;
        for key in [
            "$schema",
            "$id",
            "title",
            "schemaVersion",
            "contractVersion",
            "pluginVersion",
            "pluginId",
            "layer",
            "evidenceLevel",
            "status",
            "digestInput",
            "contractDigest",
            "service",
            "provider",
            "consumer",
            "credentials",
            "scope",
            "queryPolicy",
            "registration",
            "evidence",
            "provenance",
            "authorityBoundary",
            "layer2Gaps",
        ] {
            if !object.contains_key(key) {
                return Err(error::AwsNeptuneGraphResultError::ContractDrift);
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
            || object.get("layer").and_then(serde_json::Value::as_u64) != Some(1)
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
            || contract_digest() != CONTRACT_DIGEST
        {
            return Err(error::AwsNeptuneGraphResultError::ContractDrift);
        }

        let service = object
            .get("service")
            .and_then(serde_json::Value::as_object)
            .ok_or(error::AwsNeptuneGraphResultError::ContractDrift)?;
        if service.get("id").and_then(serde_json::Value::as_str) != Some(SERVICE_ID)
            || service.get("readOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("proposalOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("externalWrites") != Some(&serde_json::Value::Bool(false))
            || service.get("kernelAuthority") != Some(&serde_json::Value::Bool(false))
            || service.get("outcomeAdoption") != Some(&serde_json::Value::Bool(false))
        {
            return Err(error::AwsNeptuneGraphResultError::ContractDrift);
        }

        let provider = object
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .ok_or(error::AwsNeptuneGraphResultError::ContractDrift)?;
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
            return Err(error::AwsNeptuneGraphResultError::ContractDrift);
        }

        let consumer = object
            .get("consumer")
            .and_then(serde_json::Value::as_object)
            .ok_or(error::AwsNeptuneGraphResultError::ContractDrift)?;
        if consumer.get("id").and_then(serde_json::Value::as_str) != Some(CONSUMER_ID)
            || consumer.get("adoptsOutcome") != Some(&serde_json::Value::Bool(false))
            || consumer.get("adoptsWorkProduct") != Some(&serde_json::Value::Bool(false))
            || consumer.get("truthAuthority") != Some(&serde_json::Value::Bool(false))
        {
            return Err(error::AwsNeptuneGraphResultError::ContractDrift);
        }

        let credentials = object
            .get("credentials")
            .and_then(serde_json::Value::as_object)
            .ok_or(error::AwsNeptuneGraphResultError::ContractDrift)?;
        if credentials.get("serialized") != Some(&serde_json::Value::Bool(false))
            || credentials.get("rawMaterialAccepted") != Some(&serde_json::Value::Bool(false))
            || credentials.get("debugRedacted") != Some(&serde_json::Value::Bool(true))
        {
            return Err(error::AwsNeptuneGraphResultError::ContractDrift);
        }

        let query_policy = object
            .get("queryPolicy")
            .and_then(serde_json::Value::as_object)
            .ok_or(error::AwsNeptuneGraphResultError::ContractDrift)?;
        if query_policy.get("arbitraryQueryText") != Some(&serde_json::Value::Bool(false))
            || query_policy.get("writes") != Some(&serde_json::Value::Bool(false))
            || query_policy.get("deletes") != Some(&serde_json::Value::Bool(false))
            || query_policy.get("loads") != Some(&serde_json::Value::Bool(false))
            || query_policy.get("s3Reads") != Some(&serde_json::Value::Bool(false))
            || query_policy.get("variableLengthTraversals") != Some(&serde_json::Value::Bool(false))
            || query_policy.get("unboundedOutput") != Some(&serde_json::Value::Bool(false))
        {
            return Err(error::AwsNeptuneGraphResultError::ContractDrift);
        }

        let provenance = object
            .get("provenance")
            .and_then(serde_json::Value::as_object)
            .ok_or(error::AwsNeptuneGraphResultError::ContractDrift)?;
        for key in ["recording", "fixture", "loopback", "blockedEnv"] {
            if provenance.get(key).and_then(serde_json::Value::as_str)
                != Some("non_native_non_connected_non_first_party")
            {
                return Err(error::AwsNeptuneGraphResultError::ContractDrift);
            }
        }
        if provenance.get("connected") != Some(&serde_json::Value::Bool(false))
            || provenance.get("native") != Some(&serde_json::Value::Bool(false))
            || provenance.get("firstParty") != Some(&serde_json::Value::Bool(false))
        {
            return Err(error::AwsNeptuneGraphResultError::ContractDrift);
        }
        Ok(())
    }
}

/// Compile-time authority claims for this Layer-1 crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    /// Layer 1 never reports a live connection.
    pub const fn connected() -> bool {
        false
    }

    /// Layer 1 never exposes a native AWS provider.
    pub const fn native() -> bool {
        false
    }

    /// Layer 1 never reports first-party evidence.
    pub const fn first_party() -> bool {
        false
    }

    /// Layer 1 never creates a durable provider receipt.
    pub const fn provider_receipt() -> bool {
        false
    }

    /// Layer 1 never becomes kernel Truth/Consent/Effect authority.
    pub const fn kernel_authority() -> bool {
        false
    }

    /// Layer 1 never adopts an Outcome or Work Product.
    pub const fn adopts_outcome() -> bool {
        false
    }

    /// Layer 1 never adopts a verified Work Product.
    pub const fn adopts_work_product() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn contract_is_pinned_to_honest_layer_one_metadata() {
        let contract = AwsNeptuneGraphResultContract::baseline().expect("contract");
        assert_eq!(contract.digest().as_str(), CONTRACT_DIGEST);
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::provider_receipt());
        assert!(!Layer1Authority::kernel_authority());
        assert!(!Layer1Authority::adopts_outcome());
        assert!(!Layer1Authority::adopts_work_product());
    }
}
