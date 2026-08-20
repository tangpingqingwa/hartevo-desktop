//! Standalone Layer-1 AWS Marketplace entitlement result boundary.
//!
//! This crate is intentionally below Hartevo Truth, Consent, Effect, Receipt,
//! Verification, Outcome, and durable Work Product authority. It models only a
//! bounded, redacted `GetEntitlements` read, digest fences, reversible
//! registration, and a Mission-scoped proposal/record seam. Fixture, recording,
//! loopback, and `BLOCKED_ENV` transports are always non-connected,
//! non-native, and non-first-party.

#![forbid(unsafe_code)]
#![allow(
    clippy::if_not_else,
    clippy::missing_fields_in_debug,
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
    MissionAwsMarketplaceEntitlementConsumer, MissionAwsMarketplaceEntitlementResult,
    ProposalDisposition, RecordedAwsMarketplaceEntitlementResult,
};
pub use error::{AwsMarketplaceEntitlementError, AwsMarketplaceTransportError, Result};
pub use model::*;
pub use provider::{
    AwsMarketplaceEntitlementProvider, AwsMarketplaceEntitlementProviderDefinition,
    AwsMarketplaceEntitlementTransport, AwsMarketplaceOperation, BlockedEnvTransport,
    FixtureTransport, GetEntitlementsRequest, GetEntitlementsResponse, LoopbackTransport,
    RecordedRequest, RecordingTransport,
};
pub use service::{
    AwsMarketplaceEntitlementProposal, AwsMarketplaceEntitlementRegistration,
    AwsMarketplaceEntitlementResult, AwsMarketplaceEntitlementService, AwsMarketplaceRegistration,
    CapabilityDescription, EntitlementEvidenceRequest, FailureCode, FailureEvidence,
    GetEntitlementsEvidenceRequest, RegistrationStatus, RegistrationTransitionEvidence,
    VerificationFailure, VerificationReport,
};

pub type AwsMarketplaceScope = AwsMarketplaceEntitlementScope;
pub type AwsMarketplaceProvider<T> = AwsMarketplaceEntitlementProvider<T>;
pub type Cursor = PageTokenReference;
pub type AwsMarketplaceService<T> = AwsMarketplaceEntitlementService<T>;

pub const CONTRACT_SCHEMA: &str = "hartevo.aws-marketplace-entitlement-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-AWS-MARKETPLACE-ENTITLEMENT-01-L1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.aws-marketplace-entitlement-result/v1|layer=1|service=aws.marketplace.entitlement.result.read|provider=aws.marketplace.entitlement.result.recording|consumer=mission.aws-marketplace-entitlement.consumer|api=get-entitlements-2017-01-11-r1";
pub const CONTRACT_DIGEST: &str =
    "2af3c083272af4e0281c29173c47502846c54bf98d720d00aa403f75bf7e2718";
pub const PLUGIN_ID: &str = "aws.marketplace.entitlement-result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "aws.marketplace.entitlement.result.read";
pub const PROVIDER_ID: &str = "aws.marketplace.entitlement.result.recording";
pub const API_REVISION: &str = "get-entitlements-2017-01-11-r1";
pub const CONSUMER_ID: &str = "mission.aws-marketplace-entitlement.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const LAYER1_PERMISSIONS: [&str; 2] = ["aws-marketplace:GetEntitlements", "mission.scope"];
pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_PAGE_SIZE: u8 = 25;
pub const MAX_PAGES: u8 = 25;
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/aws-marketplace-entitlement-result/contract.v1.json");

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn contract_digest() -> String {
    sha256_hex(CONTRACT_DIGEST_INPUT.as_bytes())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AwsMarketplaceEntitlementContract {
    value: serde_json::Value,
}

impl AwsMarketplaceEntitlementContract {
    pub fn baseline() -> Result<Self> {
        let value = serde_json::from_str::<serde_json::Value>(CONTRACT_JSON)
            .map_err(|_| AwsMarketplaceEntitlementError::ContractDrift)?;
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
            .ok_or(AwsMarketplaceEntitlementError::ContractDrift)?;
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
                return Err(AwsMarketplaceEntitlementError::ContractDrift);
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
            || CONTRACT_DIGEST == "PENDING"
            || contract_digest() != CONTRACT_DIGEST
        {
            return Err(AwsMarketplaceEntitlementError::ContractDrift);
        }
        let service = object
            .get("service")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsMarketplaceEntitlementError::ContractDrift)?;
        if service.get("id").and_then(serde_json::Value::as_str) != Some(SERVICE_ID)
            || service.get("readOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("proposalOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("externalWrites") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsMarketplaceEntitlementError::ContractDrift);
        }
        let provider = object
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsMarketplaceEntitlementError::ContractDrift)?;
        if provider.get("id").and_then(serde_json::Value::as_str) != Some(PROVIDER_ID)
            || provider
                .get("apiRevision")
                .and_then(serde_json::Value::as_str)
                != Some(API_REVISION)
            || provider.get("connected") != Some(&serde_json::Value::Bool(false))
            || provider.get("native") != Some(&serde_json::Value::Bool(false))
            || provider.get("firstParty") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsMarketplaceEntitlementError::ContractDrift);
        }
        let consumer = object
            .get("consumer")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsMarketplaceEntitlementError::ContractDrift)?;
        if consumer.get("id").and_then(serde_json::Value::as_str) != Some(CONSUMER_ID)
            || consumer.get("adoptsOutcome") != Some(&serde_json::Value::Bool(false))
            || consumer.get("adoptsWorkProduct") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsMarketplaceEntitlementError::ContractDrift);
        }
        let credentials = object
            .get("credentials")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsMarketplaceEntitlementError::ContractDrift)?;
        if credentials.get("opaqueReference") != Some(&serde_json::Value::Bool(true))
            || credentials.get("serializable") != Some(&serde_json::Value::Bool(false))
            || credentials.get("rawMaterialRetained") != Some(&serde_json::Value::Bool(false))
        {
            return Err(AwsMarketplaceEntitlementError::ContractDrift);
        }
        for forbidden in [
            "ResolveCustomer",
            "MeterUsage",
            "purchase",
            "agreement",
            "deployment",
            "mutate_entitlement",
        ] {
            if !object
                .get("forbiddenEffects")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(forbidden)))
            {
                return Err(AwsMarketplaceEntitlementError::ContractDrift);
            }
        }
        let evidence = object
            .get("evidence")
            .and_then(serde_json::Value::as_object)
            .ok_or(AwsMarketplaceEntitlementError::ContractDrift)?;
        for key in [
            "tamperRejected",
            "replayConflictRejected",
            "revocationRejected",
        ] {
            if evidence.get(key) != Some(&serde_json::Value::Bool(true)) {
                return Err(AwsMarketplaceEntitlementError::ContractDrift);
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
        let contract = AwsMarketplaceEntitlementContract::baseline().expect("contract");
        assert_eq!(contract.digest().as_str(), CONTRACT_DIGEST);
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::durable_provider_receipt());
        assert!(!Layer1Authority::adopts_outcome());
        assert!(!Layer1Authority::adopts_work_product());
    }
}
