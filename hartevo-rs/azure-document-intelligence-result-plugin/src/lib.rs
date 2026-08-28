//! Standalone Layer-1 Azure Document Intelligence result plugin.
//!
//! This root provides a typed capability description, exact document and
//! Mission scope, reversible registration, provider replay seams, and a
//! redacted result projection. It deliberately stops before native credential
//! resolution, document submission/polling, durable provider receipts,
//! independent readback, and verified Work Product adoption.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    DocumentIntelligenceDisposition, MissionDocumentIntelligenceConsumer,
    MissionDocumentIntelligenceObservation, MissionDocumentIntelligenceResult,
};
pub use model::*;
pub use provider::{
    AzureDocumentIntelligenceProvider, AzureDocumentIntelligenceRegistration,
    AzureDocumentIntelligenceRegistrationRequest, RecordedProviderResponse, RegistrationState,
    Revocation, RevocationReason,
};
pub use service::{
    AzureDocumentIntelligenceCapability, AzureDocumentIntelligenceOperation,
    AzureDocumentIntelligenceService,
};

pub const AZURE_DOCUMENT_INTELLIGENCE_SCHEMA_VERSION: &str =
    "hartevo.azure-document-intelligence-result.contract/v1";
pub const AZURE_DOCUMENT_INTELLIGENCE_CONTRACT_VERSION: &str =
    "azure-document-intelligence-result/v1";
pub const AZURE_DOCUMENT_INTELLIGENCE_PLUGIN_VERSION: &str = "0.1.0";
pub const AZURE_DOCUMENT_INTELLIGENCE_SERVICE_ID: &str =
    "hartevo.azure.document-intelligence.result";
pub const AZURE_DOCUMENT_INTELLIGENCE_SERVICE_NAME: &str = "AzureDocumentIntelligenceService";
pub const AZURE_DOCUMENT_INTELLIGENCE_PROVIDER_ID: &str = "azure.document-intelligence";
pub const AZURE_DOCUMENT_INTELLIGENCE_PROVIDER_NAME: &str = "AzureDocumentIntelligenceProvider";
pub const MISSION_DOCUMENT_INTELLIGENCE_CONSUMER_ID: &str = "mission.document-intelligence";
pub const MISSION_DOCUMENT_INTELLIGENCE_CONSUMER_NAME: &str = "MissionDocumentIntelligenceConsumer";
pub const AZURE_DOCUMENT_INTELLIGENCE_PROVIDER_REVISION: &str =
    "azure-document-intelligence-rest-2024-11-30-r1";
pub const AZURE_DOCUMENT_INTELLIGENCE_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/azure-document-intelligence-result/azure-document-intelligence-result.v1.json"
);

pub const MAX_DOCUMENT_INTELLIGENCE_RESPONSE_BYTES: usize = 1_048_576;
pub const MAX_DOCUMENT_INTELLIGENCE_PAGE_NUMBER: u32 = 2_000;
pub const MAX_DOCUMENT_INTELLIGENCE_OUTPUT_PAGES: usize = 64;
pub const MAX_DOCUMENT_INTELLIGENCE_OUTPUT_PARAGRAPHS: usize = 128;
pub const MAX_DOCUMENT_INTELLIGENCE_OUTPUT_TABLES: usize = 32;
pub const MAX_DOCUMENT_INTELLIGENCE_OUTPUT_TABLE_CELLS: usize = 512;
pub const MAX_DOCUMENT_INTELLIGENCE_OUTPUT_FIELDS: usize = 128;
pub const MAX_DOCUMENT_INTELLIGENCE_TEXT_PREVIEW_BYTES: usize = 512;
pub const AZURE_DOCUMENT_INTELLIGENCE_LAYER2_GAPS: &[&str] = &[
    "native_credential_resolution",
    "native_document_submission",
    "native_operation_polling",
    "durable_provider_receipt",
    "independent_result_readback",
    "verified_work_product_adoption",
];

/// A checked-in, machine-readable Layer-1 contract document.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AzureDocumentIntelligenceContract {
    #[serde(rename = "$schema")]
    pub schema_uri: String,
    #[serde(rename = "$id")]
    pub contract_uri: String,
    pub title: String,
    pub description: String,
    pub schema_version: String,
    pub contract_version: String,
    pub plugin_version: String,
    pub layer: String,
    pub service_id: String,
    pub provider_id: String,
    pub consumer_id: String,
    pub scope: Vec<String>,
    pub allowlisted_models: Vec<String>,
    pub operations: Vec<String>,
    pub provenance: Vec<String>,
    pub typed_seams: ContractTypedSeams,
    pub registration: ContractRegistration,
    pub bounds: ContractBounds,
    pub redaction: ContractRedaction,
    pub authority: ContractAuthority,
    pub forbidden: Vec<String>,
    pub layer2_gaps: Vec<String>,
    pub honest_native_gap: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractTypedSeams {
    pub operation_location: String,
    pub status: Vec<String>,
    pub result: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct ContractRegistration {
    pub version_bound: bool,
    pub contract_bound: bool,
    pub provider_bound: bool,
    pub permission_bound: bool,
    pub scope_bound: bool,
    pub source_digest_bound: bool,
    pub reversible: bool,
    pub revocable: bool,
    pub fail_closed_on: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractBounds {
    pub max_response_bytes: usize,
    pub max_page_number: u32,
    pub max_output_pages: usize,
    pub max_paragraphs: usize,
    pub max_tables: usize,
    pub max_table_cells: usize,
    pub max_fields: usize,
    pub max_text_preview_bytes: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct ContractRedaction {
    pub default: String,
    pub optional: String,
    pub raw_bytes_retained: bool,
    pub raw_pii_retained: bool,
    pub sas_or_ui_links_retained: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct ContractAuthority {
    pub external_writes: bool,
    pub uploads: bool,
    pub model_training: bool,
    pub connected: bool,
    pub native: bool,
    pub durable_provider_receipt: bool,
    pub independent_read_back: bool,
    pub kernel_truth: bool,
    pub kernel_receipt: bool,
    pub kernel_verification: bool,
    pub kernel_outcome: bool,
    pub verified_work_product_adoption: bool,
    pub dashboard: bool,
    pub generic_ocr_registry: bool,
}

impl AzureDocumentIntelligenceContract {
    pub fn baseline() -> Result<Self, AzureDocumentIntelligenceError> {
        model::validate_model_constants()?;
        let contract = serde_json::from_str::<Self>(AZURE_DOCUMENT_INTELLIGENCE_CONTRACT_JSON)
            .map_err(|error| AzureDocumentIntelligenceError::Contract(error.to_string()))?;
        contract.validate()?;
        Ok(contract)
    }

    pub fn digest(&self) -> Digest {
        contract_digest()
    }

    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> Result<(), AzureDocumentIntelligenceError> {
        let expected_scope = vec![
            "tenant_id",
            "resource_name",
            "region",
            "allowlisted_model",
            "document_id",
            "source_sha256_digest",
            "inclusive_page_range",
            "project_id_and_revision",
            "mission_id_and_revision",
            "work_product_id_and_revision",
            "consent_id_and_revision_and_purpose",
            "document_intelligence_read_permission",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let expected_operations = vec![
            "describe_capabilities",
            "register",
            "revoke_registration",
            "compile_analysis_request",
            "begin_analysis_seam",
            "poll_analysis_seam",
            "project_redacted_result",
            "consume_mission_projection",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let expected_provenance = vec![
            "recording".to_owned(),
            "fixture".to_owned(),
            "loopback".to_owned(),
            "BLOCKED_ENV".to_owned(),
        ];
        let expected_status = vec![
            "not_started".to_owned(),
            "running".to_owned(),
            "succeeded".to_owned(),
            "failed".to_owned(),
            "canceled".to_owned(),
            "BLOCKED_ENV".to_owned(),
        ];
        let expected_fail_closed = vec![
            "version_drift".to_owned(),
            "contract_digest_drift".to_owned(),
            "provider_revision_drift".to_owned(),
            "permission_drift".to_owned(),
            "scope_drift".to_owned(),
            "source_digest_drift".to_owned(),
            "registration_tamper".to_owned(),
            "registration_revocation".to_owned(),
        ];
        let expected_gaps = vec![
            "native_credential_resolution".to_owned(),
            "native_document_submission".to_owned(),
            "native_operation_polling".to_owned(),
            "durable_provider_receipt".to_owned(),
            "independent_result_readback".to_owned(),
            "verified_work_product_adoption".to_owned(),
        ];
        if self.schema_version != AZURE_DOCUMENT_INTELLIGENCE_SCHEMA_VERSION
            || self.contract_version != AZURE_DOCUMENT_INTELLIGENCE_CONTRACT_VERSION
            || self.plugin_version != AZURE_DOCUMENT_INTELLIGENCE_PLUGIN_VERSION
            || self.layer != "Layer-1"
            || self.service_id != AZURE_DOCUMENT_INTELLIGENCE_SERVICE_ID
            || self.provider_id != AZURE_DOCUMENT_INTELLIGENCE_PROVIDER_ID
            || self.consumer_id != MISSION_DOCUMENT_INTELLIGENCE_CONSUMER_ID
            || self.scope != expected_scope
            || self.allowlisted_models
                != vec!["prebuilt-read".to_owned(), "prebuilt-layout".to_owned()]
            || self.operations != expected_operations
            || self.provenance != expected_provenance
            || self.typed_seams.status != expected_status
            || !self.registration.version_bound
            || !self.registration.contract_bound
            || !self.registration.provider_bound
            || !self.registration.permission_bound
            || !self.registration.scope_bound
            || !self.registration.source_digest_bound
            || !self.registration.reversible
            || !self.registration.revocable
            || self.registration.fail_closed_on != expected_fail_closed
            || self.bounds.max_response_bytes != MAX_DOCUMENT_INTELLIGENCE_RESPONSE_BYTES
            || self.bounds.max_page_number != MAX_DOCUMENT_INTELLIGENCE_PAGE_NUMBER
            || self.bounds.max_output_pages != MAX_DOCUMENT_INTELLIGENCE_OUTPUT_PAGES
            || self.bounds.max_paragraphs != MAX_DOCUMENT_INTELLIGENCE_OUTPUT_PARAGRAPHS
            || self.bounds.max_tables != MAX_DOCUMENT_INTELLIGENCE_OUTPUT_TABLES
            || self.bounds.max_table_cells != MAX_DOCUMENT_INTELLIGENCE_OUTPUT_TABLE_CELLS
            || self.bounds.max_fields != MAX_DOCUMENT_INTELLIGENCE_OUTPUT_FIELDS
            || self.bounds.max_text_preview_bytes != MAX_DOCUMENT_INTELLIGENCE_TEXT_PREVIEW_BYTES
            || self.redaction.default != "digest_only"
            || self.redaction.optional != "bounded_prefix"
            || self.redaction.raw_bytes_retained
            || self.redaction.raw_pii_retained
            || self.redaction.sas_or_ui_links_retained
            || self.authority.external_writes
            || self.authority.uploads
            || self.authority.model_training
            || self.authority.connected
            || self.authority.native
            || self.authority.durable_provider_receipt
            || self.authority.independent_read_back
            || self.authority.kernel_truth
            || self.authority.kernel_receipt
            || self.authority.kernel_verification
            || self.authority.kernel_outcome
            || self.authority.verified_work_product_adoption
            || self.authority.dashboard
            || self.authority.generic_ocr_registry
            || self.layer2_gaps != expected_gaps
            || !self.honest_native_gap.contains("BLOCKED_ENV")
            || !self.honest_native_gap.contains("Layer-2 gaps")
        {
            return Err(AzureDocumentIntelligenceError::Contract(
                "Azure Document Intelligence contract does not match the checked-in Layer-1 baseline"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

/// Failure classes for the standalone provider/service seam.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AzureDocumentIntelligenceError {
    #[error("BLOCKED_ENV: native Azure Document Intelligence authority is unavailable")]
    BlockedEnv,
    #[error("Azure Document Intelligence input is invalid: {0}")]
    InvalidInput(String),
    #[error("Azure Document Intelligence contract is invalid: {0}")]
    Contract(String),
    #[error("Azure Document Intelligence scope mismatch: {0}")]
    ScopeMismatch(String),
    #[error("Azure Document Intelligence registration is revoked")]
    RegistrationRevoked,
    #[error("Azure Document Intelligence registration is stale or drifted: {0}")]
    RegistrationDrift(String),
    #[error("Azure Document Intelligence contract digest mismatch")]
    ContractDigestMismatch,
    #[error("Azure Document Intelligence provider revision mismatch")]
    ProviderRevisionMismatch,
    #[error("Azure Document Intelligence permission mismatch")]
    PermissionMismatch,
    #[error("Azure Document Intelligence source digest mismatch")]
    SourceDigestMismatch,
    #[error("Azure Document Intelligence response was too large: {0} bytes")]
    ResponseTooLarge(usize),
    #[error("Azure Document Intelligence response could not be decoded: {0}")]
    Decode(String),
    #[error("Azure Document Intelligence provider has no recorded response")]
    NoRecordedResponse,
    #[error("Azure Document Intelligence operation location does not match the request")]
    OperationMismatch,
    #[error("Azure Document Intelligence result is unavailable for this status")]
    ResultUnavailable,
    #[error("Azure Document Intelligence recorded evidence was replayed")]
    ReplayDetected,
    #[error("Azure Document Intelligence model is not allowlisted")]
    ModelNotAllowlisted,
    #[error("Azure Document Intelligence model projection is not supported: {0}")]
    UnsupportedProjection(String),
    #[error("Azure Document Intelligence local evidence is stale or invalid")]
    StaleEvidence,
    #[error("Azure Document Intelligence model error: {0}")]
    Model(#[from] model::ModelError),
}

/// Digest of the exact checked-in contract bytes.
pub fn contract_digest() -> Digest {
    model::sha256_digest(AZURE_DOCUMENT_INTELLIGENCE_CONTRACT_JSON.as_bytes())
}

/// Digest of the plugin version string used by registration.
pub fn plugin_version_digest() -> Digest {
    model::sha256_digest(AZURE_DOCUMENT_INTELLIGENCE_PLUGIN_VERSION.as_bytes())
}

pub(crate) fn digest_serializable<T: Serialize>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("bounded contract values serialize");
    model::sha256_digest(&bytes)
}

#[cfg(test)]
mod contract_document_tests {
    use serde_json::Value;

    use super::{
        AZURE_DOCUMENT_INTELLIGENCE_CONTRACT_JSON, AZURE_DOCUMENT_INTELLIGENCE_CONTRACT_VERSION,
        AZURE_DOCUMENT_INTELLIGENCE_PLUGIN_VERSION, AZURE_DOCUMENT_INTELLIGENCE_SCHEMA_VERSION,
    };

    #[test]
    fn checked_contract_keeps_layer_one_honest() {
        let contract: Value =
            serde_json::from_str(AZURE_DOCUMENT_INTELLIGENCE_CONTRACT_JSON).expect("contract");
        assert_eq!(
            contract["schemaVersion"],
            AZURE_DOCUMENT_INTELLIGENCE_SCHEMA_VERSION
        );
        assert_eq!(
            contract["contractVersion"],
            AZURE_DOCUMENT_INTELLIGENCE_CONTRACT_VERSION
        );
        assert_eq!(
            contract["pluginVersion"],
            AZURE_DOCUMENT_INTELLIGENCE_PLUGIN_VERSION
        );
        assert_eq!(contract["layer"], "Layer-1");
        assert_eq!(contract["authority"]["connected"], false);
        assert_eq!(contract["authority"]["native"], false);
        assert_eq!(contract["authority"]["uploads"], false);
        assert_eq!(contract["redaction"]["rawBytesRetained"], false);
    }
}
