//! Standalone Layer-1 governed AWS CloudWatch Logs Insights result plugin.
//!
//! The crate owns only a typed, bounded, digest-sealed proposal boundary. It
//! does not resolve credentials, sign native SigV4 requests, execute native
//! HTTPS, export logs, retain raw events, create CloudWatch mutations, mint a
//! durable provider receipt, assert incident truth, or adopt a kernel Outcome.

#![forbid(unsafe_code)]
#![allow(
    clippy::assigning_clones,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::collapsible_if,
    clippy::format_push_string,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::redundant_closure_for_method_calls,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

pub mod consumer;
pub mod model;
pub mod provider;
pub mod query;
pub mod service;

pub use consumer::{
    ConsumerError, MissionAwsCloudWatchLogsConsumer, MissionAwsCloudWatchLogsDecision,
    MissionAwsCloudWatchLogsDecisionState, MissionAwsCloudWatchLogsResult,
    MissionAwsCloudWatchLogsResultProposal,
};
pub use model::*;
pub use provider::{
    ALLOWLISTED_ACTIONS, AwsCloudWatchLogsProvider, AwsCloudWatchLogsProviderDefinition,
    AwsCloudWatchLogsProviderIdentity, AwsCloudWatchLogsTransport,
    BlockedEnvAwsCloudWatchLogsTransport, BlockedEnvTransport, DescribeQueriesRequest,
    DescribeQueriesResponse, FakeAwsCloudWatchLogsTransport, FixtureAwsCloudWatchLogsTransport,
    FixtureTransport, GetQueryResultsRequest, GetQueryResultsResponse,
    LoopbackAwsCloudWatchLogsTransport, LoopbackTransport, ProviderDefinitionError,
    ProviderProvenance, QueryExecutionSummary, QueryFence, RecordingAwsCloudWatchLogsTransport,
    RecordingTransport, StartQueryRequest, StartQueryResponse, is_access_loss,
    provider_error_evidence, status_to_evidence,
};
pub use query::{
    AwsCloudWatchLogsQuery, AwsCloudWatchLogsQueryProposal, AwsCloudWatchLogsQueryTemplate,
    CloudWatchLogsQuery, ParameterizedQuery, QueryMode, QueryParameter, QueryParameterType,
    QueryProposalRequest, QueryTemplate, QueryTemplateKind, ResultBounds,
};
pub use service::{
    AwsCloudWatchLogsCapabilities, AwsCloudWatchLogsEvidence, AwsCloudWatchLogsProposal,
    AwsCloudWatchLogsRecord, AwsCloudWatchLogsRecordReceipt, AwsCloudWatchLogsRegistration,
    AwsCloudWatchLogsRegistrationReceipt, AwsCloudWatchLogsResultService, AwsCloudWatchLogsService,
    AwsCloudWatchLogsServiceDefinition, AwsCloudWatchLogsServiceError, AwsCloudWatchLogsVerified,
    AwsCloudWatchLogsVerifiedRecord, RegistrationError,
};

pub const AWS_CLOUDWATCH_LOGS_SCHEMA_VERSION: &str =
    "hartevo.aws-cloudwatch-logs-result.contract/v1";
pub const AWS_CLOUDWATCH_LOGS_CONTRACT_VERSION: &str = "EXT-AWS-CLOUDWATCH-LOGS-01-L1/v1";
pub const AWS_CLOUDWATCH_LOGS_PLUGIN_VERSION: &str = "1.0.0";
pub const AWS_CLOUDWATCH_LOGS_PLUGIN_ID: &str = "aws.cloudwatch.logs.result";
pub const AWS_CLOUDWATCH_LOGS_SERVICE_ID: &str = "aws.cloudwatch.logs.result.read";
pub const AWS_CLOUDWATCH_LOGS_PROVIDER_ID: &str = "aws.cloudwatch.logs.result.recording";
pub const AWS_CLOUDWATCH_LOGS_API_REVISION: &str =
    "cloudwatch-logs-start-query-get-query-results-describe-queries-1";
pub const AWS_CLOUDWATCH_LOGS_CONSUMER_ID: &str = "mission.aws-cloudwatch-logs.consumer";
pub const AWS_CLOUDWATCH_LOGS_EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const AWS_CLOUDWATCH_LOGS_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const AWS_CLOUDWATCH_LOGS_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/aws-cloudwatch-logs-result/contract.v1.json");

pub const CONTRACT_SCHEMA: &str = AWS_CLOUDWATCH_LOGS_SCHEMA_VERSION;
pub const CONTRACT_VERSION: &str = AWS_CLOUDWATCH_LOGS_CONTRACT_VERSION;
pub const PLUGIN_ID: &str = AWS_CLOUDWATCH_LOGS_PLUGIN_ID;
pub const PLUGIN_VERSION: &str = AWS_CLOUDWATCH_LOGS_PLUGIN_VERSION;
pub const SERVICE_ID: &str = AWS_CLOUDWATCH_LOGS_SERVICE_ID;
pub const PROVIDER_ID: &str = AWS_CLOUDWATCH_LOGS_PROVIDER_ID;
pub const PROVIDER_API_REVISION: &str = AWS_CLOUDWATCH_LOGS_API_REVISION;
pub const CONSUMER_ID: &str = AWS_CLOUDWATCH_LOGS_CONSUMER_ID;
pub const EVIDENCE_LEVEL: &str = AWS_CLOUDWATCH_LOGS_EVIDENCE_LEVEL;
pub const CONTRACT_JSON: &str = AWS_CLOUDWATCH_LOGS_CONTRACT_JSON;

pub fn contract_digest() -> Digest {
    model::sha256_digest(AWS_CLOUDWATCH_LOGS_CONTRACT_JSON.as_bytes())
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

    pub const fn first_party_provider() -> bool {
        false
    }

    pub const fn durable_provider_receipt() -> bool {
        false
    }

    pub const fn truth_authority() -> bool {
        false
    }

    pub const fn adopted_outcome() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_tests {
    use serde::Deserialize;

    use super::*;

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ContractDocument {
        schema_version: String,
        contract_version: String,
        plugin_version: String,
        plugin_id: String,
        layer: String,
        evidence_level: String,
        service: ServiceDocument,
        provider: ProviderDocument,
        consumer: ConsumerDocument,
        scope: ScopeDocument,
        redaction: RedactionDocument,
        authority: AuthorityDocument,
        honesty: HonestyDocument,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ServiceDocument {
        id: String,
        implementation: String,
        read_only: bool,
        proposal_only: bool,
        live_execution: bool,
        external_writes: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ProviderDocument {
        id: String,
        implementation: String,
        api_revision: String,
        allowlisted_operations: Vec<String>,
        native: bool,
        connected: bool,
        first_party: bool,
        external_writes: bool,
        sig_v4_secret: String,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ConsumerDocument {
        id: String,
        implementation: String,
        adopts_outcome: bool,
        truth_authority: bool,
        verified_work_product_adoption: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ScopeDocument {
        arbitrary_query_text: bool,
        raw_log_events: bool,
        raw_messages: bool,
        raw_stack_traces: bool,
        raw_request_bodies: bool,
        raw_pii: bool,
        raw_ptr_values: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct RedactionDocument {
        secret_material: bool,
        raw_query_text: bool,
        raw_next_token: bool,
        raw_provider_payload: bool,
        raw_log_events: bool,
        messages: bool,
        stack_traces: bool,
        request_bodies: bool,
        pii: bool,
        ptr_values: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AuthorityDocument {
        read_only: bool,
        proposal_only: bool,
        external_writes: bool,
        credential_resolution: bool,
        connected: bool,
        native: bool,
        first_party: bool,
        durable_provider_receipt: bool,
        verification_authority: bool,
        kernel_outcome_adoption: bool,
        truth_authority: bool,
        incident_authority: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct HonestyDocument {
        blocked_environment_is_native: bool,
        fixture_is_native: bool,
        recording_is_native: bool,
        loopback_is_native: bool,
        connected_claim: bool,
        native_claim: bool,
        first_party_claim: bool,
    }

    #[test]
    fn contract_document_keeps_layer_one_honest() {
        let contract = serde_json::from_str::<ContractDocument>(AWS_CLOUDWATCH_LOGS_CONTRACT_JSON)
            .expect("CloudWatch Logs contract JSON");
        assert_eq!(contract.schema_version, AWS_CLOUDWATCH_LOGS_SCHEMA_VERSION);
        assert_eq!(
            contract.contract_version,
            AWS_CLOUDWATCH_LOGS_CONTRACT_VERSION
        );
        assert_eq!(contract.plugin_version, AWS_CLOUDWATCH_LOGS_PLUGIN_VERSION);
        assert_eq!(contract.plugin_id, AWS_CLOUDWATCH_LOGS_PLUGIN_ID);
        assert_eq!(contract.layer, "Layer-1");
        assert_eq!(contract.evidence_level, AWS_CLOUDWATCH_LOGS_EVIDENCE_LEVEL);
        assert_eq!(contract.service.id, AWS_CLOUDWATCH_LOGS_SERVICE_ID);
        assert_eq!(contract.service.implementation, "AwsCloudWatchLogsService");
        assert!(contract.service.read_only);
        assert!(contract.service.proposal_only);
        assert!(!contract.service.live_execution);
        assert!(!contract.service.external_writes);
        assert_eq!(contract.provider.id, AWS_CLOUDWATCH_LOGS_PROVIDER_ID);
        assert_eq!(
            contract.provider.implementation,
            "AwsCloudWatchLogsProvider"
        );
        assert_eq!(
            contract.provider.api_revision,
            AWS_CLOUDWATCH_LOGS_API_REVISION
        );
        assert_eq!(
            contract.provider.allowlisted_operations,
            ["StartQuery", "GetQueryResults", "DescribeQueries"]
        );
        assert!(!contract.provider.native);
        assert!(!contract.provider.connected);
        assert!(!contract.provider.first_party);
        assert!(!contract.provider.external_writes);
        assert_eq!(
            contract.provider.sig_v4_secret,
            "opaque_non_serializing_secret_reference_only"
        );
        assert_eq!(contract.consumer.id, AWS_CLOUDWATCH_LOGS_CONSUMER_ID);
        assert_eq!(
            contract.consumer.implementation,
            "MissionAwsCloudWatchLogsConsumer"
        );
        assert!(!contract.consumer.adopts_outcome);
        assert!(!contract.consumer.truth_authority);
        assert!(!contract.consumer.verified_work_product_adoption);
        assert!(!contract.scope.arbitrary_query_text);
        assert!(!contract.scope.raw_log_events);
        assert!(!contract.scope.raw_messages);
        assert!(!contract.scope.raw_stack_traces);
        assert!(!contract.scope.raw_request_bodies);
        assert!(!contract.scope.raw_pii);
        assert!(!contract.scope.raw_ptr_values);
        assert!(!contract.redaction.secret_material);
        assert!(!contract.redaction.raw_query_text);
        assert!(!contract.redaction.raw_next_token);
        assert!(!contract.redaction.raw_provider_payload);
        assert!(!contract.redaction.raw_log_events);
        assert!(!contract.redaction.messages);
        assert!(!contract.redaction.stack_traces);
        assert!(!contract.redaction.request_bodies);
        assert!(!contract.redaction.pii);
        assert!(!contract.redaction.ptr_values);
        assert!(contract.authority.read_only);
        assert!(contract.authority.proposal_only);
        assert!(!contract.authority.external_writes);
        assert!(!contract.authority.credential_resolution);
        assert!(!contract.authority.connected);
        assert!(!contract.authority.native);
        assert!(!contract.authority.first_party);
        assert!(!contract.authority.durable_provider_receipt);
        assert!(!contract.authority.verification_authority);
        assert!(!contract.authority.kernel_outcome_adoption);
        assert!(!contract.authority.truth_authority);
        assert!(!contract.authority.incident_authority);
        assert!(!contract.honesty.blocked_environment_is_native);
        assert!(!contract.honesty.fixture_is_native);
        assert!(!contract.honesty.recording_is_native);
        assert!(!contract.honesty.loopback_is_native);
        assert!(!contract.honesty.connected_claim);
        assert!(!contract.honesty.native_claim);
        assert!(!contract.honesty.first_party_claim);
        assert_eq!(AWS_CLOUDWATCH_LOGS_BLOCKED_ENV, "BLOCKED_ENV");
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::first_party_provider());
        assert!(!Layer1Authority::durable_provider_receipt());
        assert!(!Layer1Authority::truth_authority());
        assert!(!Layer1Authority::adopted_outcome());
    }
}
