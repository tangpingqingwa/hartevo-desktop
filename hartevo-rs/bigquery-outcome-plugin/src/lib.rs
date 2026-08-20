//! Layer-1 governed BigQuery analytical-result plugin.
//!
//! This crate is deliberately standalone. It owns a typed service definition,
//! a provider seam for recorded/fake/loopback job responses, and a Mission
//! consumer that produces bounded evidence for a later decision. It does not
//! execute a live Google request, hold credentials, write a table, mint a
//! Hartevo Receipt, adopt an Outcome, or claim Connected/native authority.

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

mod consumer;
mod model;
mod provider;
mod query;
mod service;

#[cfg(test)]
mod adversarial_tests;

pub use consumer::{
    ConsumerError, ConsumerRegistration, MissionBigQueryResult, MissionBigQueryResultConsumer,
    MissionResultState,
};
pub use model::{
    AdoptionAvailability, AnalyticalResultAuthority, BigQueryRegistration, BigQueryScope,
    BoundedRow, CellType, ConsumerId, DatasetId, Digest, ErrorSeverity, EvidenceDigests,
    GoogleAuthKind, JobId, JobMetadata, JobReference, JobState, Location, MissionId, ModelError,
    OpaquePageToken, PermissionFence, ProjectId, ProviderErrorEvidence, ProviderErrorKind,
    ProviderId, QueryErrorEvidence, QuerySchema, QuerySchemaField, RedactedCell, RegistrationState,
    ResultBounds, ResultStatus, Revision, SecretReference, ServiceId, TableId, WorkProductId,
};
pub use provider::{
    BigQueryJobsProvider, BigQueryJobsTransport, BigQueryProvider, BigQueryProviderDefinition,
    BlockedEnvTransport, FakeBigQueryTransport, JobsGetQueryResultsRequest, JobsQueryRequest,
    JobsQueryResponse, LoopbackTransport, ProviderDefinitionError, ProviderProvenance,
    QueryResultPage, RecordingBigQueryTransport, TransportError,
};
pub use query::{
    BigQueryQueryProposal, ParameterizedSelect, QueryCompileError, QueryMode, QueryParameter,
    QueryParameterType, QueryProposalRequest,
};
pub use service::{
    BigQueryOutcomeService, BigQueryResultProposal, BigQueryResultService,
    BigQueryServiceDefinition, BigQueryServiceError, PartialReason, ResultEvidence,
    ResultProjection, RetryEvidence, RetryPolicy,
};

pub const BIGQUERY_OUTCOME_SCHEMA_VERSION: &str = "hartevo-bigquery-outcome-contract/v1";
pub const BIGQUERY_OUTCOME_CONTRACT_VERSION: &str = "bigquery-outcome-e1/v1";
pub const BIGQUERY_OUTCOME_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/bigquery-outcome/bigquery-outcome.v1.json");
pub const BIGQUERY_OUTCOME_SERVICE_ID: &str = "bigquery.outcome.result";
pub const BIGQUERY_OUTCOME_PROVIDER_ID: &str = "bigquery.jobs.query-results";
pub const BIGQUERY_OUTCOME_CONSUMER_ID: &str = "mission.bigquery.result.consumer";
pub const BIGQUERY_OUTCOME_EVIDENCE_LEVEL: &str = "E1";
pub const BIGQUERY_OUTCOME_BLOCKED_ENV: &str = "BLOCKED_ENV";

/// The authority boundary exposed by Layer 1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    /// Layer 1 never reports a connected Google account.
    pub const fn connected() -> bool {
        false
    }

    /// Layer 1 never executes a native BigQuery request.
    pub const fn native_provider() -> bool {
        false
    }

    /// Layer 1 never creates a durable native receipt.
    pub const fn durable_receipt() -> bool {
        false
    }

    /// Layer 1 never adopts an Outcome or becomes Truth authority.
    pub const fn adopted_outcome() -> bool {
        false
    }

    /// Layer 1 returns evidence for a decision; it is not Hartevo Truth.
    pub const fn truth_authority() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_document_tests {
    use serde::Deserialize;

    use super::{
        BIGQUERY_OUTCOME_BLOCKED_ENV, BIGQUERY_OUTCOME_CONSUMER_ID, BIGQUERY_OUTCOME_CONTRACT_JSON,
        BIGQUERY_OUTCOME_CONTRACT_VERSION, BIGQUERY_OUTCOME_EVIDENCE_LEVEL,
        BIGQUERY_OUTCOME_PROVIDER_ID, BIGQUERY_OUTCOME_SCHEMA_VERSION, BIGQUERY_OUTCOME_SERVICE_ID,
        Layer1Authority,
    };

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ContractDocument {
        schema_version: String,
        contract_version: String,
        evidence_level: String,
        layer: u8,
        service: ServiceDocument,
        provider: ProviderDocument,
        consumer: ConsumerDocument,
        native_claims: NativeClaims,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ServiceDocument {
        id: String,
        read_only: bool,
        live_execution: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ProviderDocument {
        id: String,
        native: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ConsumerDocument {
        id: String,
        adopts_outcome: bool,
        truth_authority: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct NativeClaims {
        connected: bool,
        native_provider: bool,
        durable_receipt: bool,
        adopted_outcome: bool,
        blocked_environment_is_native: bool,
    }

    #[test]
    fn contract_document_keeps_layer_one_honest() {
        let document = serde_json::from_str::<ContractDocument>(BIGQUERY_OUTCOME_CONTRACT_JSON)
            .expect("BigQuery contract JSON");
        assert_eq!(document.schema_version, BIGQUERY_OUTCOME_SCHEMA_VERSION);
        assert_eq!(document.contract_version, BIGQUERY_OUTCOME_CONTRACT_VERSION);
        assert_eq!(document.evidence_level, BIGQUERY_OUTCOME_EVIDENCE_LEVEL);
        assert_eq!(document.layer, 1);
        assert_eq!(document.service.id, BIGQUERY_OUTCOME_SERVICE_ID);
        assert!(document.service.read_only);
        assert!(!document.service.live_execution);
        assert_eq!(document.provider.id, BIGQUERY_OUTCOME_PROVIDER_ID);
        assert!(!document.provider.native);
        assert_eq!(document.consumer.id, BIGQUERY_OUTCOME_CONSUMER_ID);
        assert!(!document.consumer.adopts_outcome);
        assert!(!document.consumer.truth_authority);
        assert!(!document.native_claims.connected);
        assert!(!document.native_claims.native_provider);
        assert!(!document.native_claims.durable_receipt);
        assert!(!document.native_claims.adopted_outcome);
        assert!(!document.native_claims.blocked_environment_is_native);
        assert_eq!(BIGQUERY_OUTCOME_BLOCKED_ENV, "BLOCKED_ENV");
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::durable_receipt());
        assert!(!Layer1Authority::adopted_outcome());
        assert!(!Layer1Authority::truth_authority());
    }
}
