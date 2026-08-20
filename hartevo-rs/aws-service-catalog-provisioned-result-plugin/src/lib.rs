//! Standalone Layer-1 governed AWS Service Catalog provisioned-product result.
//!
//! The crate exposes only bounded read/proposal/record/verify seams. It has no
//! AWS SDK, native SigV4 resolver, HTTPS client, provisioning effect, durable
//! provider receipt, independent read-back, or Work Product/Outcome authority.

#![forbid(unsafe_code)]
#![allow(
    clippy::assigning_clones,
    clippy::collapsible_if,
    clippy::format_push_string,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::missing_fields_in_debug,
    clippy::needless_pass_by_value,
    clippy::redundant_closure_for_method_calls,
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

pub use consumer::{
    MissionAwsServiceCatalogConsumer, MissionAwsServiceCatalogResult, ProposalDisposition,
    RecordedAwsServiceCatalogResult as MissionRecordedAwsServiceCatalogResult,
};
pub use error::{AwsServiceCatalogError, AwsServiceCatalogTransportError, Result};
pub use model::*;
pub use provider::{
    AwsServiceCatalogOperation, AwsServiceCatalogProvider, AwsServiceCatalogProviderDefinition,
    AwsServiceCatalogTransport, BlockedEnvTransport, DescribeProvisionedProductRequest,
    DescribeProvisionedProductResponse, DescribeRecordRequest, DescribeRecordResponse,
    FixtureTransport, ListRecordHistoryRequest, ListRecordHistoryResponse, LoopbackTransport,
    RecordedRequest, RecordingTransport, SearchProvisionedProductsRequest,
    SearchProvisionedProductsResponse,
};
pub use service::{
    AwsServiceCatalogEvidenceRequest, AwsServiceCatalogProvisionedResultProposal,
    AwsServiceCatalogProvisionedResultRegistration, AwsServiceCatalogProvisionedResultService,
    AwsServiceCatalogRegistration, AwsServiceCatalogRegistrationAlias, CapabilityDescription,
    EvidenceDigests, FailureEvidence, RecordedAwsServiceCatalogResult, RegistrationStatus,
    RegistrationTransitionEvidence, VerificationFailure, VerificationReport,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.aws-service-catalog-provisioned-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-AWS-SERVICE-CATALOG-01-L1/v1";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const PLUGIN_ID: &str = "aws.service-catalog.provisioned-result";
pub const SERVICE_ID: &str = "aws.service-catalog.provisioned-result.read";
pub const PROVIDER_ID: &str = "aws.service-catalog.provisioned-result.recording";
pub const CONSUMER_ID: &str = "mission.aws-service-catalog-provisioned-result.consumer";
pub const API_REVISION: &str =
    "service-catalog-search-describe-list-history-describe-record-2015-12-10-r1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.aws-service-catalog-provisioned-result/v1|layer=1|service=aws.service-catalog.provisioned-result.read|provider=aws.service-catalog.provisioned-result.recording|consumer=mission.aws-service-catalog-provisioned-result.consumer|api=service-catalog-search-describe-list-history-describe-record-2015-12-10-r1";
pub const CONTRACT_DIGEST: &str =
    "469ade8927a1e175fdb7dc85e2b80b2f08f1805ade5860efd0a359e170c2b38d";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const LAYER1_PERMISSIONS: [&str; 5] = [
    "servicecatalog:SearchProvisionedProducts",
    "servicecatalog:DescribeProvisionedProduct",
    "servicecatalog:ListRecordHistory",
    "servicecatalog:DescribeRecord",
    "mission.scope",
];
pub const MAX_SEARCH_PAGE_SIZE: u16 = model::MAX_SEARCH_PAGE_SIZE;
pub const MAX_HISTORY_PAGE_SIZE: u16 = model::MAX_HISTORY_PAGE_SIZE;
pub const MAX_PAGES: u16 = model::MAX_PAGES;
pub const MAX_RESPONSE_BYTES: u64 = model::MAX_RESPONSE_BYTES;
pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/aws-service-catalog-provisioned-result/aws-service-catalog-provisioned-result.v1.json"
);

pub fn contract_digest() -> String {
    model::Digest::from_text(CONTRACT_DIGEST_INPUT).to_string()
}

/// Validates the checked-in versioned contract and the Layer-1 authority
/// flags used by the Rust boundary.
pub fn validate_contract() -> Result<()> {
    let document = serde_json::from_str::<serde_json::Value>(CONTRACT_JSON)
        .map_err(|_| AwsServiceCatalogError::ContractDrift)?;
    let object = document
        .as_object()
        .ok_or(AwsServiceCatalogError::ContractDrift)?;
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
        "evidence",
        "provenance",
        "authorityBoundary",
        "forbiddenEffects",
        "layer2Gaps",
    ] {
        if !object.contains_key(key) {
            return Err(AwsServiceCatalogError::ContractDrift);
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
        return Err(AwsServiceCatalogError::ContractDrift);
    }
    let service = object
        .get("service")
        .and_then(serde_json::Value::as_object)
        .ok_or(AwsServiceCatalogError::ContractDrift)?;
    if service.get("type").and_then(serde_json::Value::as_str)
        != Some("AwsServiceCatalogProvisionedResultService")
        || service.get("id").and_then(serde_json::Value::as_str) != Some(SERVICE_ID)
        || service.get("readOnly") != Some(&serde_json::Value::Bool(true))
        || service.get("externalWrites") != Some(&serde_json::Value::Bool(false))
        || service.get("outcomeAdoption") != Some(&serde_json::Value::Bool(false))
    {
        return Err(AwsServiceCatalogError::ContractDrift);
    }
    let provider = object
        .get("provider")
        .and_then(serde_json::Value::as_object)
        .ok_or(AwsServiceCatalogError::ContractDrift)?;
    if provider.get("type").and_then(serde_json::Value::as_str) != Some("AwsServiceCatalogProvider")
        || provider.get("id").and_then(serde_json::Value::as_str) != Some(PROVIDER_ID)
        || provider
            .get("apiRevision")
            .and_then(serde_json::Value::as_str)
            != Some(API_REVISION)
        || provider.get("connected") != Some(&serde_json::Value::Bool(false))
        || provider.get("native") != Some(&serde_json::Value::Bool(false))
        || provider.get("firstParty") != Some(&serde_json::Value::Bool(false))
        || provider.get("providerReceipt") != Some(&serde_json::Value::Bool(false))
    {
        return Err(AwsServiceCatalogError::ContractDrift);
    }
    let consumer = object
        .get("consumer")
        .and_then(serde_json::Value::as_object)
        .ok_or(AwsServiceCatalogError::ContractDrift)?;
    if consumer.get("type").and_then(serde_json::Value::as_str)
        != Some("MissionAwsServiceCatalogConsumer")
        || consumer.get("id").and_then(serde_json::Value::as_str) != Some(CONSUMER_ID)
        || consumer.get("adoptsOutcome") != Some(&serde_json::Value::Bool(false))
        || consumer.get("adoptsWorkProduct") != Some(&serde_json::Value::Bool(false))
    {
        return Err(AwsServiceCatalogError::ContractDrift);
    }
    let forbidden = object
        .get("forbiddenEffects")
        .and_then(serde_json::Value::as_array)
        .ok_or(AwsServiceCatalogError::ContractDrift)?;
    for effect in [
        "ProvisionProduct",
        "UpdateProvisionedProduct",
        "TerminateProvisionedProduct",
        "ExecuteProvisionedProductPlan",
        "resolve_native_credentials",
        "live_https",
        "adopt_work_product",
        "adopt_outcome",
    ] {
        if !forbidden.iter().any(|value| value.as_str() == Some(effect)) {
            return Err(AwsServiceCatalogError::ContractDrift);
        }
    }
    Ok(())
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

    pub const fn outcome_adoption() -> bool {
        false
    }

    pub const fn work_product_adoption() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn checked_contract_is_layer_one_and_non_native() {
        validate_contract().expect("Service Catalog contract validates");
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::durable_provider_receipt());
        assert!(!Layer1Authority::outcome_adoption());
        assert!(!Layer1Authority::work_product_adoption());
    }
}
