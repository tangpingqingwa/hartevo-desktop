//! Standalone Layer-1 governed AWS AppSync API result boundary.
//!
//! This crate is intentionally below Hartevo Truth, Consent, Effect, Receipt,
//! Verification, Outcome, and durable Work Product authority. It models only
//! bounded AppSync API/configuration metadata, schema/deployment/association
//! digests, reversible registration, redacted request/cost receipts, and a
//! Mission-scoped proposal/record seam. Recording, fixture, loopback, and
//! `BLOCKED_ENV` transports are always non-connected, non-native, and
//! non-first-party.

#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::collapsible_if,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::missing_fields_in_debug,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
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
pub mod service;

pub use consumer::{
    MissionAwsAppSyncConsumer, MissionAwsAppSyncResult, ProposalDisposition,
    RecordedAwsAppSyncResult,
};
pub use error::{AwsAppSyncApiResultError, AwsAppSyncTransportError, Result};
pub use model::*;
pub use provider::{
    AssociationResponse, AwsAppSyncOperation, AwsAppSyncProvider, AwsAppSyncProviderDefinition,
    AwsAppSyncTransport, BlockedEnvTransport, Cursor, FixtureTransport, GetApiRequest,
    GetApiResponse, GetSchemaCreationStatusRequest, GetSchemaCreationStatusResponse,
    ListDataSourcesRequest, ListDataSourcesResponse, ListGraphqlApisRequest,
    ListGraphqlApisResponse, ListResolversRequest, ListResolversResponse, LoopbackTransport,
    RecordedRequest, RecordingTransport,
};
pub use service::{
    AppSyncEvidenceRequest, AwsAppSyncApiResultProposal, AwsAppSyncApiResultRegistration,
    AwsAppSyncApiResultService, AwsAppSyncRegistration, CapabilityDescription, FailureEvidence,
    RegistrationStatus, RegistrationTransitionEvidence, VerificationFailure, VerificationReport,
};

pub type AwsAppSyncScope = AwsAppSyncApiScope;
pub type AwsAppSyncApiProjection = ApiMetadata;
pub type AwsAppSyncSchemaProjection = SchemaDeploymentMetadata;
pub type AwsAppSyncService<T> = AwsAppSyncApiResultService<T>;
pub type AwsAppSyncApiResult = AwsAppSyncApiResultProposal;

pub const CONTRACT_SCHEMA: &str = "hartevo.aws-appsync-api-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-AWS-APPSYNC-01-L1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.aws-appsync-api-result/v1|layer=1|service=aws.appsync.api.result.read|provider=aws.appsync.api.result.recording|consumer=mission.aws-appsync-api-result.consumer|api=appsync-list-graphql-apis-get-api-schema-association-2020-07-07-r1";
pub const CONTRACT_DIGEST: &str =
    "e3f7738a3b24966584a5ccb2ec1c4fd5fb6aa77350cbefd141f9a27a4a079e25";
pub const PLUGIN_ID: &str = "aws.appsync.api.result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "aws.appsync.api.result.read";
pub const PROVIDER_ID: &str = "aws.appsync.api.result.recording";
pub const API_REVISION: &str = "appsync-list-graphql-apis-get-api-schema-association-2020-07-07-r1";
pub const CONSUMER_ID: &str = "mission.aws-appsync-api-result.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const LAYER1_PERMISSIONS: [&str; 6] = [
    "appsync:ListGraphqlApis",
    "appsync:GetApi",
    "appsync:GetSchemaCreationStatus",
    "appsync:ListDataSources",
    "appsync:ListResolvers",
    "mission.scope",
];
pub const FORBIDDEN_PERMISSIONS: [&str; 13] = [
    "appsync:CreateApi",
    "appsync:UpdateApi",
    "appsync:DeleteApi",
    "appsync:StartSchemaCreation",
    "appsync:DeleteApiCache",
    "appsync:CreateDataSource",
    "appsync:DeleteDataSource",
    "appsync:CreateResolver",
    "appsync:DeleteResolver",
    "appsync:GraphQL",
    "appsync:EventPublish",
    "appsync:EventSubscribe",
    "outcome.adopt",
];
pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_PAGE_SIZE: u16 = 25;
pub const MAX_PAGES: u16 = 8;
pub const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
pub const MAX_ASSOCIATIONS: usize = 256;
pub const MAX_STALENESS_SECONDS: i64 = 60 * 60;
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/aws-appsync-api-result/aws-appsync-api-result.v1.json"
);

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn contract_digest() -> String {
    sha256_hex(CONTRACT_DIGEST_INPUT.as_bytes())
}

pub(crate) fn valid_release(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsAppSyncApiResultContract {
    value: serde_json::Value,
}

impl AwsAppSyncApiResultContract {
    pub fn baseline() -> Result<Self> {
        let value = serde_json::from_str::<serde_json::Value>(CONTRACT_JSON)
            .map_err(|_| AwsAppSyncApiResultError::ContractDrift)?;
        let contract = Self { value };
        contract.validate()?;
        Ok(contract)
    }

    pub fn value(&self) -> &serde_json::Value {
        &self.value
    }

    pub fn digest(&self) -> Digest {
        Digest::from_text(CONTRACT_DIGEST_INPUT)
    }

    pub fn validate(&self) -> Result<()> {
        let object = self
            .value
            .as_object()
            .ok_or(AwsAppSyncApiResultError::ContractDrift)?;
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
                return Err(AwsAppSyncApiResultError::ContractDrift);
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
            || contract_digest() != CONTRACT_DIGEST
        {
            return Err(AwsAppSyncApiResultError::ContractDrift);
        }
        let service = object
            .get("service")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsAppSyncApiResultError::ContractDrift)?;
        if service.get("id").and_then(serde_json::Value::as_str) != Some(SERVICE_ID)
            || service.get("readOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("proposalOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("externalWrites") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsAppSyncApiResultError::ContractDrift);
        }
        let provider = object
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsAppSyncApiResultError::ContractDrift)?;
        if provider.get("id").and_then(serde_json::Value::as_str) != Some(PROVIDER_ID)
            || provider
                .get("apiRevision")
                .and_then(serde_json::Value::as_str)
                != Some(API_REVISION)
            || provider.get("connected") != Some(&serde_json::Value::Bool(false))
            || provider.get("native") != Some(&serde_json::Value::Bool(false))
            || provider.get("firstParty") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsAppSyncApiResultError::ContractDrift);
        }
        let consumer = object
            .get("consumer")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsAppSyncApiResultError::ContractDrift)?;
        if consumer.get("id").and_then(serde_json::Value::as_str) != Some(CONSUMER_ID)
            || consumer.get("adoptsOutcome") != Some(&serde_json::Value::Bool(false))
            || consumer.get("adoptsWorkProduct") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsAppSyncApiResultError::ContractDrift);
        }
        for forbidden in [
            "GraphQL",
            "EventPublish",
            "EventSubscribe",
            "CreateApi",
            "UpdateApi",
            "DeleteApi",
            "CreateResolver",
            "DeleteResolver",
            "CreateDataSource",
            "DeleteDataSource",
            "export_raw_schema",
            "adopt_verified_work_product",
        ] {
            if !object
                .get("forbiddenEffects")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(forbidden)))
            {
                return Err(AwsAppSyncApiResultError::ContractDrift);
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

    pub const fn durable_provider_receipt() -> bool {
        false
    }

    pub const fn executes_graphql() -> bool {
        false
    }

    pub const fn mutates_appsync() -> bool {
        false
    }

    pub const fn adopts_outcome() -> bool {
        false
    }

    pub const fn adopts_work_product() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn contract_is_pinned_to_layer_one_and_honest_provenance() {
        let contract = AwsAppSyncApiResultContract::baseline().expect("contract");
        assert_eq!(contract.digest().as_str(), CONTRACT_DIGEST);
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::durable_provider_receipt());
        assert!(!Layer1Authority::executes_graphql());
        assert!(!Layer1Authority::mutates_appsync());
        assert!(!Layer1Authority::adopts_outcome());
        assert!(!Layer1Authority::adopts_work_product());
    }
}
