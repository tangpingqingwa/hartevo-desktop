//! Standalone Layer-1 governed Cloudinary asset evidence result plugin.
//!
//! The crate exposes a typed read/proposal/recording seam for bounded
//! Cloudinary resource, usage, transformation, and delivery metadata. It does
//! not resolve native credentials, make live HTTPS calls, download media,
//! execute signed URLs, mutate Cloudinary, retain PII, or adopt an Outcome or
//! Work Product.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
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

mod consumer;
mod error;
mod model;
mod provider;
mod service;

pub use consumer::{
    MissionCloudinaryAssetConsumer, MissionCloudinaryAssetResult, MissionCloudinaryResult,
    MissionCloudinaryResultConsumer, ProposalDisposition, RecordedCloudinaryAssetResult,
};
pub use error::{CloudinaryAssetResultError, CloudinaryTransportError, Result};
pub use model::*;
pub use provider::{
    BlockedEnvCloudinaryTransport, BlockedEnvTransport, CloudinaryAssetResultRequest,
    CloudinaryProvider, CloudinaryProviderDefinition, CloudinaryProviderFailure,
    CloudinaryProviderResponse, CloudinaryProviderResult, CloudinaryReadRequest,
    CloudinaryRetryPolicy, CloudinaryTransport, FakeCloudinaryTransport, FakeTransport,
    FixtureCloudinaryTransport, FixtureTransport, LoopbackCloudinaryTransport, LoopbackTransport,
    RecordedRequest, RecordingTransport,
};
pub use service::{
    CapabilityDescription, CloudinaryAssetResult, CloudinaryAssetResultEvidence,
    CloudinaryAssetResultProposal, CloudinaryAssetResultRegistration,
    CloudinaryAssetResultRegistrationBinding, CloudinaryAssetResultService, CloudinaryRegistration,
    CloudinaryService, CloudinaryVerificationRequest, PermissionSnapshot, RegistrationStatus,
    RegistrationTransitionEvidence, VerificationFailure, VerificationReport,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.cloudinary-asset-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-CLOUDINARY-01-L1/v1";
pub const PLUGIN_ID: &str = "cloudinary.asset.result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "cloudinary.asset.result.read";
pub const PROVIDER_ID: &str = "cloudinary.asset.result.recording";
pub const API_REVISION: &str = "cloudinary-admin-resource-usage-transformation-delivery-read-r1";
pub const CONSUMER_ID: &str = "mission.cloudinary-asset-result.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.cloudinary-asset-result/v1|layer=1|service=cloudinary.asset.result.read|provider=cloudinary.asset.result.recording|consumer=mission.cloudinary-asset-result.consumer|api=cloudinary-admin-resource-usage-transformation-delivery-read-r1";
pub const CONTRACT_DIGEST: &str =
    "6220e88f553910863ed7cc67a50bde3d6363a557321bcc6f25ab5eeb36d79b98";
pub const LAYER1_PERMISSIONS: [&str; 5] = [
    "cloudinary:resources.read",
    "cloudinary:usage.read",
    "cloudinary:transformations.read",
    "cloudinary:delivery.metadata.read",
    "mission.scope",
];
pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: u16 = 4;
pub const MAX_RESPONSE_BYTES: u64 = 1_048_576;
pub const MAX_COLLECTION_ITEMS: usize = 64;
pub const MAX_RETRY_ATTEMPTS: u8 = 3;
pub const MAX_BACKOFF_SECONDS: u64 = 30;
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/cloudinary-asset-result/cloudinary-asset-result.v1.json"
);

pub fn plugin_version_digest() -> Digest {
    Digest::from_parts(
        "cloudinary-asset-result-plugin-version/v1",
        &[("version", PLUGIN_VERSION.to_owned())],
    )
}

pub fn contract_digest() -> Digest {
    Digest::from_text(CONTRACT_DIGEST_INPUT)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloudinaryAssetResultContract {
    value: serde_json::Value,
}

pub type CloudinaryContract = CloudinaryAssetResultContract;

impl CloudinaryAssetResultContract {
    pub fn baseline() -> Result<Self> {
        let value = serde_json::from_str::<serde_json::Value>(CONTRACT_JSON)
            .map_err(|_| CloudinaryAssetResultError::ContractDrift)?;
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
            .ok_or(CloudinaryAssetResultError::ContractDrift)?;
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
            "paginationAndRetry",
            "projection",
            "receipts",
            "evidence",
            "provenance",
            "authorityBoundary",
            "forbiddenEffects",
            "layer2Gaps",
            "honestNativeGap",
        ] {
            if !object.contains_key(key) {
                return Err(CloudinaryAssetResultError::ContractDrift);
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
            return Err(CloudinaryAssetResultError::ContractDrift);
        }
        let service = object
            .get("service")
            .and_then(serde_json::Value::as_object)
            .ok_or(CloudinaryAssetResultError::ContractDrift)?;
        if service.get("id").and_then(serde_json::Value::as_str) != Some(SERVICE_ID)
            || service.get("readOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("proposalOnly") != Some(&serde_json::Value::Bool(true))
            || service.get("externalWrites") != Some(&serde_json::Value::Bool(false))
        {
            return Err(CloudinaryAssetResultError::ContractDrift);
        }
        let provider = object
            .get("provider")
            .and_then(serde_json::Value::as_object)
            .ok_or(CloudinaryAssetResultError::ContractDrift)?;
        if provider.get("id").and_then(serde_json::Value::as_str) != Some(PROVIDER_ID)
            || provider
                .get("apiRevision")
                .and_then(serde_json::Value::as_str)
                != Some(API_REVISION)
            || provider.get("connected") != Some(&serde_json::Value::Bool(false))
            || provider.get("native") != Some(&serde_json::Value::Bool(false))
            || provider.get("firstParty") != Some(&serde_json::Value::Bool(false))
        {
            return Err(CloudinaryAssetResultError::ContractDrift);
        }
        let consumer = object
            .get("consumer")
            .and_then(serde_json::Value::as_object)
            .ok_or(CloudinaryAssetResultError::ContractDrift)?;
        if consumer.get("id").and_then(serde_json::Value::as_str) != Some(CONSUMER_ID)
            || consumer.get("adoptsOutcome") != Some(&serde_json::Value::Bool(false))
            || consumer.get("adoptsWorkProduct") != Some(&serde_json::Value::Bool(false))
        {
            return Err(CloudinaryAssetResultError::ContractDrift);
        }
        for forbidden in [
            "upload",
            "update",
            "delete",
            "create_transformation",
            "execute_signed_url",
            "verify_signed_url",
            "download_raw_media",
            "retain_pii",
            "adopt_verified_work_product",
        ] {
            if !object
                .get("forbiddenEffects")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(forbidden)))
            {
                return Err(CloudinaryAssetResultError::ContractDrift);
            }
        }
        Ok(())
    }
}

/// Layer-1's authority is intentionally all-false for native/connected and
/// adoption claims. These constants are used by tests and contract gates.
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

    pub const fn signed_url_execution() -> bool {
        false
    }

    pub const fn delivery_guarantee() -> bool {
        false
    }

    pub const fn raw_media_download() -> bool {
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
        let contract = CloudinaryAssetResultContract::baseline().expect("contract");
        assert_eq!(contract.digest().as_str(), CONTRACT_DIGEST);
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::durable_provider_receipt());
        assert!(!Layer1Authority::signed_url_execution());
        assert!(!Layer1Authority::delivery_guarantee());
        assert!(!Layer1Authority::raw_media_download());
        assert!(!Layer1Authority::adopts_outcome());
        assert!(!Layer1Authority::adopts_work_product());
    }
}
