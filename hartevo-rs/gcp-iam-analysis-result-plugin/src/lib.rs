//! Layer-1 governed Google Cloud IAM analysis result plugin.
//!
//! This standalone root provides typed, read-only Cloud Asset
//! `searchAllIamPolicies` and `analyzeIamPolicy` seams. It emits bounded,
//! digest-only provider evidence for a Mission. It does not resolve live
//! credentials, claim Connected/native authority, mutate IAM, retain raw
//! policy or principal data, issue kernel receipts, or adopt an Outcome.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![allow(
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::items_after_statements,
    clippy::match_same_arms,
    clippy::return_self_not_must_use
)]

use hartevo_plugin_runtime::{
    CompatibilityPolicy, ConsumerDefinition, ConsumerId, Digest as RuntimeDigest,
    PluginContributions, PluginDefinition, PluginError, PluginId, PluginScope, PluginVersion,
    ProviderCardinality, ProviderDefinition, ProviderId, ServiceDefinition, ServiceId,
};
use serde_json::Value;
use thiserror::Error;

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;
pub mod transport;

pub use consumer::{
    MissionGcpIamConsumer, MissionGcpIamObservation, MissionGcpIamResult, MissionGcpIamState,
};
pub use model::*;
pub use provider::{
    GcpCloudAssetProvider, GcpCloudAssetProviderDefinition, GcpCloudAssetProviderError,
    GcpCloudAssetProviderTransport, GcpCloudAssetRegistration, GcpIamProviderError,
    GcpIamRegistration, GcpProviderDefinitionError, RegistrationState,
};
pub use service::{
    GcpIamAnalysisCapability, GcpIamAnalysisOperation, GcpIamAnalysisProposal,
    GcpIamAnalysisRecord, GcpIamAnalysisService, GcpIamAnalysisVerification,
};
pub use transport::{
    BlockedEnvGcpCloudAssetTransport, BlockedEnvTransport, FakeGcpCloudAssetTransport,
    FixtureGcpCloudAssetTransport, GcpCloudAssetPayload, GcpCloudAssetRequest,
    GcpCloudAssetResponse, GcpCloudAssetTransport, GcpTransportError,
    LoopbackGcpCloudAssetTransport, RecordingGcpCloudAssetTransport,
};

pub const GCP_IAM_ANALYSIS_SCHEMA_VERSION: &str = "hartevo.gcp-iam-analysis-result-contract/v1";
pub const GCP_IAM_ANALYSIS_CONTRACT_VERSION: &str = "gcp-iam-analysis-result-e1/v1";
pub const GCP_IAM_ANALYSIS_EVIDENCE_LEVEL: &str = "E1";
pub const GCP_IAM_ANALYSIS_PLUGIN_VERSION: &str = "0.1.0";
pub const GCP_IAM_ANALYSIS_PLUGIN_ID: &str = "gcp-iam-analysis-result";
pub const GCP_IAM_ANALYSIS_SERVICE_ID: &str = "gcp.iam-analysis.result";
pub const GCP_IAM_ANALYSIS_SERVICE_NAME: &str = "GcpIamAnalysisService";
pub const GCP_IAM_ANALYSIS_SERVICE_VERSION: &str = "1.0.0";
pub const GCP_IAM_ANALYSIS_PROVIDER_ID: &str = "gcp.cloud-asset";
pub const GCP_IAM_ANALYSIS_PROVIDER_NAME: &str = "GcpCloudAssetProvider";
pub const GCP_IAM_ANALYSIS_PROVIDER_VERSION: &str = "1.0.0";
pub const GCP_IAM_ANALYSIS_PROVIDER_REVISION: &str = "gcp-cloud-asset-iam-analysis-r1";
pub const GCP_IAM_ANALYSIS_API_VERSION: &str = "v1";
pub const MISSION_GCP_IAM_CONSUMER_ID: &str = "mission.gcp-iam-analysis";
pub const MISSION_GCP_IAM_CONSUMER_NAME: &str = "MissionGcpIamConsumer";
pub const GCP_IAM_ANALYSIS_SERVICE_SCHEMA: &str = "hartevo.gcp-iam-analysis-result-service/v1";
pub const GCP_IAM_ANALYSIS_PROVIDER_SCHEMA: &str = "hartevo.gcp-iam-analysis-result-provider/v1";
pub const GCP_IAM_ANALYSIS_CONSUMER_SCHEMA: &str = "hartevo.mission-gcp-iam-analysis-consumer/v1";
pub const GCP_IAM_ANALYSIS_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const GCP_IAM_ANALYSIS_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/gcp-iam-analysis-result/gcp-iam-analysis-result.v1.json"
);

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum GcpIamAnalysisError {
    #[error("the checked-in GCP IAM analysis contract is invalid: {0}")]
    Contract(String),
    #[error(transparent)]
    Model(#[from] GcpIamModelError),
    #[error(transparent)]
    Provider(#[from] GcpCloudAssetProviderError),
    #[error("the GCP IAM analysis proposal or record digest does not match")]
    EvidenceDigestMismatch,
    #[error("the GCP IAM analysis evidence is stale for the Mission scope")]
    StaleEvidence,
    #[error("the GCP IAM analysis evidence scope does not match")]
    ScopeMismatch,
    #[error("the plugin runtime rejected the GCP IAM analysis contribution: {0}")]
    Plugin(#[from] PluginError),
}

#[must_use]
pub fn contract_digest() -> Digest {
    Digest::from_bytes(GCP_IAM_ANALYSIS_CONTRACT_JSON.as_bytes())
}

#[must_use]
pub fn plugin_version() -> PluginVersion {
    PluginVersion::new(1, 0, 0)
}

#[must_use]
pub fn plugin_version_digest() -> Digest {
    Digest::from_text(GCP_IAM_ANALYSIS_PLUGIN_VERSION)
}

#[must_use]
pub fn provider_capability_digest() -> Digest {
    Digest::from_fields(
        "gcp-cloud-asset-capabilities/v1",
        &[
            GCP_IAM_ANALYSIS_API_VERSION.to_owned(),
            GcpCloudAssetOperation::SearchAllIamPolicies
                .api_method()
                .to_owned(),
            GcpCloudAssetOperation::AnalyzeIamPolicy
                .api_method()
                .to_owned(),
            "read_only=true".to_owned(),
            "raw_policy=false".to_owned(),
            "raw_principal=false".to_owned(),
        ],
    )
}

#[must_use]
pub fn provider_definition_digest_for(provenance: ProviderProvenance) -> Digest {
    Digest::from_fields(
        "gcp-cloud-asset-provider-definition/v1",
        &[
            GCP_IAM_ANALYSIS_PROVIDER_ID.to_owned(),
            GCP_IAM_ANALYSIS_PROVIDER_VERSION.to_owned(),
            GCP_IAM_ANALYSIS_PROVIDER_REVISION.to_owned(),
            GCP_IAM_ANALYSIS_API_VERSION.to_owned(),
            provider_capability_digest().as_str().to_owned(),
            format!("{provenance:?}"),
        ],
    )
}

#[must_use]
pub fn provider_definition_digest() -> Digest {
    provider_definition_digest_for(ProviderProvenance::Fixture)
}

/// Parsed and checked-in contract document. Runtime code depends on this
/// baseline so a contract-only drift fails closed before registration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GcpIamAnalysisContract {
    document: Value,
}

impl GcpIamAnalysisContract {
    pub fn baseline() -> Result<Self, GcpIamAnalysisError> {
        let document = serde_json::from_str::<Value>(GCP_IAM_ANALYSIS_CONTRACT_JSON)
            .map_err(|error| GcpIamAnalysisError::Contract(error.to_string()))?;
        let contract = Self { document };
        contract.validate()?;
        Ok(contract)
    }

    #[must_use]
    pub fn document(&self) -> &Value {
        &self.document
    }

    #[must_use]
    pub fn digest(&self) -> Digest {
        contract_digest()
    }

    pub fn validate(&self) -> Result<(), GcpIamAnalysisError> {
        let operations = [
            "describe_capabilities",
            "register",
            "revoke_registration",
            "propose_iam_analysis",
            "record_evidence",
            "verify_evidence",
            "consume_observation",
        ];
        let provider_operations = ["searchAllIamPolicies", "analyzeIamPolicy"];
        let accepted_provenance = ["fixture", "recording", "loopback", "blocked_env"];
        let scope_fields = [
            "organization",
            "folders",
            "projects",
            "resourceName",
            "resourceAncestry",
            "principalClass",
            "principalDigest",
            "policyBindingFingerprint",
            "roleFingerprint",
            "analysisQuery",
            "missionIdAndRevision",
            "projectIdAndRevision",
            "workProductIdAndRevision",
            "permissionDigest",
            "consentDigest",
            "secretReferenceDigest",
            "credentialRevision",
            "hierarchyRevision",
            "policyRevision",
            "queryDigest",
        ];
        let authority_false = [
            "connected",
            "nativeProvider",
            "externalWrite",
            "effect",
            "durableReceipt",
            "verification",
            "truthAuthority",
            "outcome",
            "workProductAdoption",
            "effectiveAuthorization",
        ]
        .iter()
        .all(|field| self.document["authority"][*field] == Value::Bool(false));
        let layer2_gaps = self
            .document
            .get("layer2Gaps")
            .and_then(Value::as_array)
            .is_some_and(|values| !values.is_empty());
        let honest_gap = self
            .document
            .get("honestNativeGap")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let valid = self.document["schemaVersion"] == GCP_IAM_ANALYSIS_SCHEMA_VERSION
            && self.document["contractVersion"] == GCP_IAM_ANALYSIS_CONTRACT_VERSION
            && self.document["evidenceLevel"] == GCP_IAM_ANALYSIS_EVIDENCE_LEVEL
            && self.document["layer"] == 1
            && self.document["service"]["id"] == GCP_IAM_ANALYSIS_SERVICE_ID
            && self.document["service"]["name"] == GCP_IAM_ANALYSIS_SERVICE_NAME
            && self.document["service"]["version"] == GCP_IAM_ANALYSIS_SERVICE_VERSION
            && self.document["service"]["readOnly"] == Value::Bool(true)
            && self.document["service"]["native"] == Value::Bool(false)
            && string_array(&self.document["service"]["operations"]) == operations
            && self.document["provider"]["id"] == GCP_IAM_ANALYSIS_PROVIDER_ID
            && self.document["provider"]["name"] == GCP_IAM_ANALYSIS_PROVIDER_NAME
            && self.document["provider"]["version"] == GCP_IAM_ANALYSIS_PROVIDER_VERSION
            && self.document["provider"]["providerRevision"] == GCP_IAM_ANALYSIS_PROVIDER_REVISION
            && self.document["provider"]["apiVersion"] == GCP_IAM_ANALYSIS_API_VERSION
            && string_array(&self.document["provider"]["operations"]) == provider_operations
            && accepted_provenance.iter().all(|value| {
                self.document["provider"]["acceptedProvenance"]
                    .as_array()
                    .is_some_and(|values| values.iter().any(|item| item == value))
            })
            && self.document["provider"]["native"] == Value::Bool(false)
            && self.document["provider"]["connected"] == Value::Bool(false)
            && self.document["provider"]["secretValuesRead"] == Value::Bool(false)
            && self.document["provider"]["credentialMaterialRetained"] == Value::Bool(false)
            && self.document["provider"]["liveCredentialResolution"] == Value::Bool(false)
            && self.document["provider"]["serviceAccountCreation"] == Value::Bool(false)
            && self.document["provider"]["policyMutation"] == Value::Bool(false)
            && self.document["provider"]["roleGrantRevoke"] == Value::Bool(false)
            && self.document["provider"]["effectiveAuthorizationClaim"] == Value::Bool(false)
            && scope_fields.iter().all(|field| {
                self.document["scope"]["required"]
                    .as_array()
                    .is_some_and(|values| values.iter().any(|item| item == field))
            })
            && self.document["scope"]["principalAddressesRetained"] == Value::Bool(false)
            && self.document["scope"]["rawResourcePayloadRetained"] == Value::Bool(false)
            && self.document["queries"]["searchAllIamPolicies"]["readOnly"] == Value::Bool(true)
            && self.document["queries"]["analyzeIamPolicy"]["readOnly"] == Value::Bool(true)
            && self.document["queries"]["analyzeIamPolicy"]["identityAddress"] == "not_retained"
            && self.document["evidence"]["rawPolicyJson"] == Value::Bool(false)
            && self.document["evidence"]["rawPrincipalAddresses"] == Value::Bool(false)
            && self.document["evidence"]["personalInformation"] == Value::Bool(false)
            && self.document["evidence"]["rawProviderPayload"] == Value::Bool(false)
            && self.document["evidence"]["rawPageToken"] == Value::Bool(false)
            && self.document["evidence"]["rawGraphEdges"] == Value::Bool(false)
            && self.document["registration"]["reversible"] == Value::Bool(true)
            && self.document["registration"]["revocable"] == Value::Bool(true)
            && self.document["nativeGap"]["status"] == GCP_IAM_ANALYSIS_BLOCKED_ENV
            && self.document["nativeGap"]["fixtureRecordingLoopbackAreNative"]
                == Value::Bool(false)
            && authority_false
            && layer2_gaps
            && honest_gap.contains("BLOCKED_ENV")
            && honest_gap.contains("setIamPolicy")
            && honest_gap.contains("service accounts")
            && honest_gap.contains("principal addresses")
            && honest_gap.contains("Truth")
            && honest_gap.contains("Outcome");
        if valid {
            Ok(())
        } else {
            Err(GcpIamAnalysisError::Contract(
                "checked-in GCP IAM analysis contract does not match the Layer-1 baseline"
                    .to_owned(),
            ))
        }
    }
}

fn string_array(value: &Value) -> Vec<&str> {
    value
        .as_array()
        .map(|values| values.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

/// Builds the reversible plugin-runtime contribution for one Project/Mission
/// generation. The runtime contribution contains descriptors only; no
/// provider handle or credential authority crosses this boundary.
pub fn plugin_definition(scope: PluginScope) -> Result<PluginDefinition, GcpIamAnalysisError> {
    let plugin_id = PluginId::new(GCP_IAM_ANALYSIS_PLUGIN_ID)?;
    let service_id = ServiceId::new(GCP_IAM_ANALYSIS_SERVICE_ID)?;
    let provider_id = ProviderId::new(GCP_IAM_ANALYSIS_PROVIDER_ID)?;
    let consumer_id = ConsumerId::new(MISSION_GCP_IAM_CONSUMER_ID)?;
    let version = plugin_version();
    let contributions = PluginContributions {
        services: vec![ServiceDefinition::read_only(
            service_id.clone(),
            version,
            RuntimeDigest::from_text(GCP_IAM_ANALYSIS_SERVICE_SCHEMA),
            ProviderCardinality::Singleton,
            CompatibilityPolicy::SameMajor,
        )?],
        providers: vec![ProviderDefinition::new(
            provider_id,
            service_id.clone(),
            version,
            RuntimeDigest::from_text(GCP_IAM_ANALYSIS_PROVIDER_SCHEMA),
        )?],
        consumers: vec![ConsumerDefinition::command(
            consumer_id,
            service_id,
            version,
            RuntimeDigest::from_text(GCP_IAM_ANALYSIS_CONSUMER_SCHEMA),
        )?],
        events: Vec::new(),
        ui_surfaces: Vec::new(),
    };
    Ok(PluginDefinition::new(
        plugin_id,
        version,
        scope,
        contributions,
    )?)
}

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
    pub const fn external_write() -> bool {
        false
    }

    #[must_use]
    pub const fn durable_receipt() -> bool {
        false
    }

    #[must_use]
    pub const fn verification() -> bool {
        false
    }

    #[must_use]
    pub const fn truth_authority() -> bool {
        false
    }

    #[must_use]
    pub const fn effective_authorization() -> bool {
        false
    }

    #[must_use]
    pub const fn adopted_outcome() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_document_tests {
    use super::*;

    #[test]
    fn checked_in_contract_validates() {
        let contract = GcpIamAnalysisContract::baseline().expect("contract");
        assert_eq!(contract.digest(), contract_digest());
        assert_eq!(GCP_IAM_ANALYSIS_BLOCKED_ENV, "BLOCKED_ENV");
    }

    #[test]
    fn layer_one_authority_is_false() {
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::external_write());
        assert!(!Layer1Authority::durable_receipt());
        assert!(!Layer1Authority::verification());
        assert!(!Layer1Authority::truth_authority());
        assert!(!Layer1Authority::effective_authorization());
        assert!(!Layer1Authority::adopted_outcome());
    }
}
