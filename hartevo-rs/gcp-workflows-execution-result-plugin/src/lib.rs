//! Standalone Layer-1 governed Google Cloud Workflows execution-result plugin.
//!
//! This crate exposes typed list/get read, proposal, record, verification, and
//! Mission observation seams.  It never resolves credentials, calls Google
//! Cloud, creates/cancels/retries/resumes executions, invokes callbacks,
//! retains workflow arguments/results/definitions/raw stack traces, claims
//! Connected/native authority, or adopts a kernel Outcome.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
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
    clippy::type_complexity,
    clippy::unnecessary_wraps
)]

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::*;
pub use model::*;
pub use provider::*;
pub use service::*;

pub const GCP_WORKFLOWS_EXECUTION_SCHEMA_VERSION: &str =
    "hartevo.gcp-workflows-execution-result-contract/v1";
pub const GCP_WORKFLOWS_EXECUTION_CONTRACT_VERSION: &str = "gcp-workflows-execution-result/v1";
pub const GCP_WORKFLOWS_EXECUTION_PLUGIN_ID: &str = "gcp-workflows-execution-result";
pub const GCP_WORKFLOWS_EXECUTION_PLUGIN_VERSION_TEXT: &str = "0.1.0";
pub const GCP_WORKFLOWS_EXECUTION_SERVICE_ID: &str = "gcp.workflows.execution-result";
pub const GCP_WORKFLOWS_EXECUTION_SERVICE_NAME: &str = "GcpWorkflowsExecutionService";
pub const GCP_WORKFLOWS_EXECUTION_PROVIDER_ID: &str = "gcp.workflows.executions";
pub const GCP_WORKFLOWS_EXECUTION_PROVIDER_VERSION_TEXT: &str = "1.0.0";
pub const GCP_WORKFLOWS_EXECUTION_PROVIDER_SCHEMA: &str =
    "hartevo.gcp-workflows-executions-provider/v1";
pub const MISSION_GCP_WORKFLOW_CONSUMER_ID: &str = "mission.gcp.workflows.execution-result";
pub const MISSION_GCP_WORKFLOW_CONSUMER_SCHEMA: &str = "hartevo.mission-gcp-workflow-consumer/v1";
pub const GCP_WORKFLOWS_EXECUTION_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const GCP_WORKFLOWS_EXECUTION_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/gcp-workflows-execution-result/gcp-workflows-execution-result.v1.json"
);

pub fn contract_digest() -> Digest {
    Digest::from_bytes(GCP_WORKFLOWS_EXECUTION_CONTRACT_JSON.as_bytes())
}

pub fn plugin_version_digest() -> Digest {
    Digest::from_text(GCP_WORKFLOWS_EXECUTION_PLUGIN_VERSION_TEXT)
}

pub fn plugin_version() -> &'static str {
    GCP_WORKFLOWS_EXECUTION_PLUGIN_VERSION_TEXT
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    pub const fn connected() -> bool {
        false
    }

    pub const fn native_provider() -> bool {
        false
    }

    pub const fn first_party() -> bool {
        false
    }

    pub const fn credential_resolution() -> bool {
        false
    }

    pub const fn external_writes() -> bool {
        false
    }

    pub const fn creates_executions() -> bool {
        false
    }

    pub const fn cancels_executions() -> bool {
        false
    }

    pub const fn retries_executions() -> bool {
        false
    }

    pub const fn resumes_executions() -> bool {
        false
    }

    pub const fn raw_arguments() -> bool {
        false
    }

    pub const fn raw_results() -> bool {
        false
    }

    pub const fn raw_stack_traces() -> bool {
        false
    }

    pub const fn durable_native_receipt() -> bool {
        false
    }

    pub const fn independent_native_readback() -> bool {
        false
    }

    pub const fn adopted_outcome() -> bool {
        false
    }

    pub const fn work_product_adoption() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_document_tests {
    use serde::Deserialize;

    use super::{
        GCP_WORKFLOWS_EXECUTION_BLOCKED_ENV, GCP_WORKFLOWS_EXECUTION_CONTRACT_JSON,
        GCP_WORKFLOWS_EXECUTION_CONTRACT_VERSION, GCP_WORKFLOWS_EXECUTION_PROVIDER_ID,
        GCP_WORKFLOWS_EXECUTION_SCHEMA_VERSION, GCP_WORKFLOWS_EXECUTION_SERVICE_ID,
        Layer1Authority, contract_digest,
    };

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ContractDocument {
        schema_version: String,
        contract_version: String,
        layer: u8,
        service: ServiceDocument,
        provider: ProviderDocument,
        authority: AuthorityDocument,
        honest_native_gap: String,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ServiceDocument {
        id: String,
        read_only: bool,
        live_execution: bool,
        connected: bool,
        native: bool,
        creates_executions: bool,
        cancels_executions: bool,
        retries_executions: bool,
        resumes_executions: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ProviderDocument {
        id: String,
        native: bool,
        connected: bool,
        first_party: bool,
        live_credential_resolution: bool,
        raw_arguments: bool,
        raw_results: bool,
        raw_stack_traces: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AuthorityDocument {
        external_writes: bool,
        connected: bool,
        native_provider: bool,
        credential_resolution: bool,
        durable_native_receipt: bool,
        independent_native_readback: bool,
        kernel_outcome_adoption: bool,
        work_product_adoption: bool,
    }

    #[test]
    fn contract_is_layer_one_and_honest() {
        let document =
            serde_json::from_str::<ContractDocument>(GCP_WORKFLOWS_EXECUTION_CONTRACT_JSON)
                .expect("GCP Workflows contract JSON");
        assert_eq!(
            document.schema_version,
            GCP_WORKFLOWS_EXECUTION_SCHEMA_VERSION
        );
        assert_eq!(
            document.contract_version,
            GCP_WORKFLOWS_EXECUTION_CONTRACT_VERSION
        );
        assert_eq!(document.layer, 1);
        assert_eq!(document.service.id, GCP_WORKFLOWS_EXECUTION_SERVICE_ID);
        assert!(document.service.read_only);
        assert!(!document.service.live_execution);
        assert!(!document.service.connected);
        assert!(!document.service.native);
        assert!(!document.service.creates_executions);
        assert!(!document.service.cancels_executions);
        assert!(!document.service.retries_executions);
        assert!(!document.service.resumes_executions);
        assert_eq!(document.provider.id, GCP_WORKFLOWS_EXECUTION_PROVIDER_ID);
        assert!(!document.provider.native);
        assert!(!document.provider.connected);
        assert!(!document.provider.first_party);
        assert!(!document.provider.live_credential_resolution);
        assert!(!document.provider.raw_arguments);
        assert!(!document.provider.raw_results);
        assert!(!document.provider.raw_stack_traces);
        assert!(!document.authority.external_writes);
        assert!(!document.authority.connected);
        assert!(!document.authority.native_provider);
        assert!(!document.authority.credential_resolution);
        assert!(!document.authority.durable_native_receipt);
        assert!(!document.authority.independent_native_readback);
        assert!(!document.authority.kernel_outcome_adoption);
        assert!(!document.authority.work_product_adoption);
        assert!(document.honest_native_gap.contains("Layer 1"));
        assert_eq!(GCP_WORKFLOWS_EXECUTION_BLOCKED_ENV, "BLOCKED_ENV");
        assert_eq!(contract_digest().len(), 64);
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::credential_resolution());
        assert!(!Layer1Authority::external_writes());
        assert!(!Layer1Authority::raw_arguments());
        assert!(!Layer1Authority::raw_results());
        assert!(!Layer1Authority::adopted_outcome());
    }
}
