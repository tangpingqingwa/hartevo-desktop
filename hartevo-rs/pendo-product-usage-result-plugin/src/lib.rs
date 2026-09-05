//! Standalone Layer-1 governed Pendo product-usage result plugin.
//!
//! The crate exposes typed aggregate-only read, proposal, record, and verify
//! projections for bounded page, feature, and guide adoption evidence. It has
//! no native credential resolver, HTTPS client, visitor-row path, PII export,
//! event or guide/segment mutation, dashboard, causal authority, Truth, or
//! Outcome authority.

#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::float_cmp)]
#![allow(clippy::if_not_else)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::result_large_err)]
#![allow(clippy::similar_names)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::too_many_lines)]

mod consumer;
mod model;
mod provider;
mod service;

pub use consumer::{
    MissionPendoUsageConsumer, MissionPendoUsageConsumerError, MissionPendoUsageResult,
    MissionPendoUsageResultState,
};
pub use model::{
    AccountScope, AdoptionMetric, ApplicationId, Binding, BindingId, ConsentScope, Digest,
    EvidenceClassification, EvidenceState, MAX_BUCKETS, MAX_DIAGNOSTIC_BYTES, MAX_IDENTIFIER_BYTES,
    MAX_REQUESTS_PER_SCOPE, MAX_RESPONSE_BYTES, MAX_ROWS, MAX_STALENESS_SECONDS,
    MAX_TIME_WINDOW_DAYS, MAX_TIME_WINDOW_SECONDS, MissionBinding, MissionId, ModelError,
    PendoAggregate, PendoAggregateBucket, PendoPermission, PendoProductUsageScope,
    PendoReadProjection, PendoReadReceipt, PendoRegistration, PendoReportMetadata,
    PendoUsageRecommendation, PendoUsageRequest, ProjectBinding, ProjectId, ProviderErrorKind,
    ProviderProvenance, RecommendationDisposition, RedactionSummary, RegistrationRevocation,
    RegistrationState, Revision, ScopedReference, SecretReference, SegmentScope, SubscriptionId,
    TargetKind, TargetReference, TimeWindow, Timestamp, VisitorKind, WorkProductBinding,
    WorkProductId, canonical_digest, sha256_digest,
};
pub use provider::{
    BlockedEnvPendoTransport, FakePendoTransport, FixturePendoTransport, LoopbackPendoTransport,
    PENDO_AGGREGATION_PATH, PENDO_API_ORIGIN, PendoHttpMethod, PendoHttpResponse, PendoPayload,
    PendoProvider, PendoProviderDefinition, PendoProviderError, PendoProviderRead,
    PendoReadRequest, PendoTransport, PendoTransportError, ProviderDefinitionError,
    RecordingPendoTransport,
};
pub use service::{
    PendoObservationReceipt, PendoProductUsageEvidence, PendoProductUsageProposal,
    PendoProductUsageResultService, PendoProductUsageServiceDefinition,
    PendoProductUsageServiceError, PendoServiceError, PendoVerification,
};

pub const PENDO_PRODUCT_USAGE_RESULT_SCHEMA_VERSION: &str = "hartevo.pendo-product-usage-result/v1";
pub const PENDO_PRODUCT_USAGE_RESULT_CONTRACT_VERSION: &str = "pendo-product-usage-result-e1/v1";
pub const PENDO_PRODUCT_USAGE_RESULT_PLUGIN_VERSION: &str = "0.1.0";
pub const PENDO_PRODUCT_USAGE_RESULT_CONTRACT_PATH: &str =
    "contracts/plugins/pendo-product-usage-result/pendo-product-usage-result.v1.json";
pub const PENDO_PRODUCT_USAGE_RESULT_SERVICE_ID: &str = "pendo.product-usage.result";
pub const PENDO_PRODUCT_USAGE_RESULT_SERVICE_VERSION: &str = "1.0.0";
pub const PENDO_PRODUCT_USAGE_RESULT_PROVIDER_ID: &str = "pendo.product-usage.aggregate";
pub const PENDO_PRODUCT_USAGE_RESULT_PROVIDER_VERSION: &str = "1.0.0";
pub const PENDO_PRODUCT_USAGE_RESULT_API_REVISION: &str = "pendo-engage-aggregation-v1";
pub const PENDO_PRODUCT_USAGE_RESULT_CONSUMER_ID: &str = "mission.pendo.product-usage";
pub const PENDO_PRODUCT_USAGE_RESULT_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const PENDO_PRODUCT_USAGE_RESULT_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/pendo-product-usage-result/pendo-product-usage-result.v1.json"
);

#[must_use]
pub fn contract_digest() -> Digest {
    sha256_digest(PENDO_PRODUCT_USAGE_RESULT_CONTRACT_JSON.as_bytes())
}

/// Layer 1 deliberately exposes no native, connected, first-party, or kernel
/// authority. The projections are evidence for a decision only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    #[must_use]
    pub const fn connected() -> bool {
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
    pub const fn durable_provider_receipt() -> bool {
        false
    }

    #[must_use]
    pub const fn independent_readback() -> bool {
        false
    }

    #[must_use]
    pub const fn adopted_work_product() -> bool {
        false
    }

    #[must_use]
    pub const fn adopted_outcome() -> bool {
        false
    }

    #[must_use]
    pub const fn causal_claims() -> bool {
        false
    }

    #[must_use]
    pub const fn external_writes() -> bool {
        false
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ContractValidationError {
    #[error("Pendo contract JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Pendo contract is missing {0}")]
    Missing(&'static str),
    #[error("Pendo contract drifted at {0}")]
    Drift(&'static str),
}

#[must_use = "contract validation should be checked"]
pub fn validate_contract() -> Result<(), ContractValidationError> {
    let document: serde_json::Value =
        serde_json::from_str(PENDO_PRODUCT_USAGE_RESULT_CONTRACT_JSON)?;
    if document["schemaVersion"] != PENDO_PRODUCT_USAGE_RESULT_SCHEMA_VERSION {
        return Err(ContractValidationError::Drift("schemaVersion"));
    }
    if document["contractVersion"] != PENDO_PRODUCT_USAGE_RESULT_CONTRACT_VERSION {
        return Err(ContractValidationError::Drift("contractVersion"));
    }
    if document["pluginVersion"] != PENDO_PRODUCT_USAGE_RESULT_PLUGIN_VERSION
        || document["layer"] != 1
    {
        return Err(ContractValidationError::Drift("identity"));
    }
    if document["service"]["id"] != PENDO_PRODUCT_USAGE_RESULT_SERVICE_ID
        || document["service"]["version"] != PENDO_PRODUCT_USAGE_RESULT_SERVICE_VERSION
        || document["provider"]["id"] != PENDO_PRODUCT_USAGE_RESULT_PROVIDER_ID
        || document["provider"]["version"] != PENDO_PRODUCT_USAGE_RESULT_PROVIDER_VERSION
        || document["consumer"]["id"] != PENDO_PRODUCT_USAGE_RESULT_CONSUMER_ID
    {
        return Err(ContractValidationError::Drift("typed identities"));
    }
    for field in [
        "readOnly",
        "proposalOnly",
        "aggregateOnly",
        "connected",
        "nativeProvider",
        "firstParty",
        "durableProviderReceipt",
        "kernelAuthority",
        "truthAuthority",
        "outcomeAuthority",
        "externalWrites",
        "causalClaims",
    ] {
        let authority = document["authority"]
            .get(field)
            .ok_or(ContractValidationError::Missing("authority"))?;
        let expected = matches!(field, "readOnly" | "proposalOnly" | "aggregateOnly");
        if authority != expected {
            return Err(ContractValidationError::Drift("authority"));
        }
    }
    let provider_reads = document["provider"]["allowlistedReads"].as_array().ok_or(
        ContractValidationError::Missing("provider.allowlistedReads"),
    )?;
    for (method, path) in [
        ("POST", PENDO_AGGREGATION_PATH),
        ("GET", "/api/v1/page"),
        ("GET", "/api/v1/feature"),
        ("GET", "/api/v1/guide"),
    ] {
        if !provider_reads.iter().any(|read| {
            read["method"] == method && read["path"] == path && read["mutates"] == false
        }) {
            return Err(ContractValidationError::Drift("provider.allowlistedReads"));
        }
    }
    if document["provider"]["allowlistedWrites"] != serde_json::json!([])
        || document["allowlist"]["writes"] != serde_json::json!([])
    {
        return Err(ContractValidationError::Drift("writes"));
    }
    for field in [
        "versionBound",
        "contractDigestBound",
        "providerDigestBound",
        "permissionDigestBound",
        "scopeDigestBound",
        "queryDigestBound",
        "secretReferenceDigestBound",
        "reversible",
        "revocable",
        "oldProposalsInvalidAfterRevocation",
    ] {
        if document["registration"].get(field) != Some(&serde_json::Value::Bool(true)) {
            return Err(ContractValidationError::Drift("registration"));
        }
    }
    for field in [
        "connected",
        "nativeProvider",
        "firstParty",
        "httpsTransport",
        "durableProviderReceipt",
        "independentReadback",
        "adoptedWorkProduct",
        "adoptedOutcome",
        "blockedEnvironmentIsNative",
    ] {
        if document["nativeClaims"].get(field) != Some(&serde_json::Value::Bool(false)) {
            return Err(ContractValidationError::Drift("nativeClaims"));
        }
    }
    Ok(())
}

pub type PendoScope = PendoProductUsageScope;
pub type PendoService<T> = PendoProductUsageResultService<T>;

#[cfg(test)]
mod contract_tests {
    use super::{
        Layer1Authority, PENDO_PRODUCT_USAGE_RESULT_BLOCKED_ENV,
        PENDO_PRODUCT_USAGE_RESULT_CONTRACT_JSON, contract_digest, validate_contract,
    };

    #[test]
    fn checked_in_contract_is_valid_and_non_native() {
        validate_contract().expect("contract validation");
        assert!(!contract_digest().is_empty());
        assert_eq!(PENDO_PRODUCT_USAGE_RESULT_BLOCKED_ENV, "BLOCKED_ENV");
        assert!(PENDO_PRODUCT_USAGE_RESULT_CONTRACT_JSON.contains("rawVisitorRows"));
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::external_writes());
        assert!(!Layer1Authority::causal_claims());
    }
}
