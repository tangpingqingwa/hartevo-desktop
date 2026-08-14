//! Layer-1 ClickHouse analytical outcome proposal boundary.
//!
//! The crate is intentionally standalone. It binds one HTTPS ClickHouse
//! endpoint, cluster, database, table, schema revision, typed bounded query,
//! Project/Mission/Work Product scope, and opaque credential reference. It
//! accepts only recorded, fake, loopback, or `BLOCKED_ENV` provider evidence.
//! It never resolves credentials, executes native HTTP, mutates ClickHouse,
//! cancels a query, creates a Hartevo Receipt, adopts a Work Product, or claims
//! Connected/native/first-party authority.

#![forbid(unsafe_code)]
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
    ConsumerError, ConsumerRegistration, MissionClickHouseOutcome,
    MissionClickHouseOutcomeConsumer, MissionClickHouseResult, MissionClickHouseResultConsumer,
    MissionResultState,
};
pub use model::{
    AdoptionAvailability, AnalyticalResultAuthority, BoundedRow, CellType, ClickHouseAuthKind,
    ClickHouseRegistration, ClickHouseScope, ClickHouseType, ColumnSchema, ConsumerId, DatabaseId,
    Digest, ErrorSeverity, EvidenceDigests, Host, MissionId, ModelError, PermissionFence,
    ProjectId, ProviderErrorEvidence, ProviderErrorKind, QueryErrorEvidence, QueryId, QueryMode,
    QueryProgress, QuerySchema, QuerySchemaField, QueryStatistics, QueryStatus, QuerySummary,
    RedactedCell, RegistrationRevocation, RegistrationState, ResultBounds, ResultStatus, Revision,
    SchemaId, SecretReference, ServiceId, TableId, WorkProductId,
};
pub use provider::{
    BlockedEnvTransport, ClickHouseHttpProvider, ClickHouseHttpTransport, ClickHouseProvider,
    ClickHouseProviderAdapter, ClickHouseProviderDefinition, ClickHouseQueryRequest,
    ClickHouseQueryResponse, FakeClickHouseTransport, LoopbackClickHouseTransport,
    ProviderDefinitionError, ProviderProvenance, RecordingClickHouseTransport, TransportError,
};
pub use query::{
    ClickHouseQuery, ClickHouseQueryKind, ClickHouseQueryProposal, ParameterizedSelect,
    QueryCompileError, QueryParameter, QueryParameterType, QueryProposalRequest,
};
pub use service::{
    ClickHouseOutcomeService, ClickHouseResultProposal, ClickHouseResultService,
    ClickHouseServiceDefinition, ClickHouseServiceError, PartialReason, ResultEvidence,
    ResultProjection, RetryEvidence, RetryPolicy, RetryPolicyError,
};

pub const CLICKHOUSE_OUTCOME_SCHEMA_VERSION: &str = "hartevo-clickhouse-outcome-contract/v1";
pub const CLICKHOUSE_OUTCOME_CONTRACT_VERSION: &str = "clickhouse-outcome-e1/v1";
pub const CLICKHOUSE_OUTCOME_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/clickhouse-outcome/clickhouse-outcome.v1.json");
pub const CLICKHOUSE_OUTCOME_SERVICE_ID: &str = "clickhouse.outcome.result";
pub const CLICKHOUSE_OUTCOME_PROVIDER_ID: &str = "clickhouse.http.query";
pub const CLICKHOUSE_OUTCOME_CONSUMER_ID: &str = "mission.clickhouse.outcome.consumer";
pub const CLICKHOUSE_OUTCOME_EVIDENCE_LEVEL: &str = "E1";
pub const CLICKHOUSE_OUTCOME_BLOCKED_ENV: &str = "BLOCKED_ENV";

/// Layer 1 exposes evidence below the kernel and below native provider
/// authority. Every flag is intentionally hard-coded false.
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

    pub const fn durable_receipt() -> bool {
        false
    }

    pub const fn adopted_outcome() -> bool {
        false
    }

    pub const fn truth_authority() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_document_tests {
    use serde::Deserialize;

    use super::{
        CLICKHOUSE_OUTCOME_BLOCKED_ENV, CLICKHOUSE_OUTCOME_CONSUMER_ID,
        CLICKHOUSE_OUTCOME_CONTRACT_JSON, CLICKHOUSE_OUTCOME_CONTRACT_VERSION,
        CLICKHOUSE_OUTCOME_EVIDENCE_LEVEL, CLICKHOUSE_OUTCOME_PROVIDER_ID,
        CLICKHOUSE_OUTCOME_SCHEMA_VERSION, CLICKHOUSE_OUTCOME_SERVICE_ID, Layer1Authority,
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
        https_only: bool,
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
        first_party_provider: bool,
        durable_receipt: bool,
        adopted_outcome: bool,
        blocked_environment_is_native: bool,
    }

    #[test]
    fn contract_document_keeps_layer_one_honest() {
        let document = serde_json::from_str::<ContractDocument>(CLICKHOUSE_OUTCOME_CONTRACT_JSON)
            .expect("ClickHouse contract JSON");
        assert_eq!(document.schema_version, CLICKHOUSE_OUTCOME_SCHEMA_VERSION);
        assert_eq!(
            document.contract_version,
            CLICKHOUSE_OUTCOME_CONTRACT_VERSION
        );
        assert_eq!(document.evidence_level, CLICKHOUSE_OUTCOME_EVIDENCE_LEVEL);
        assert_eq!(document.layer, 1);
        assert_eq!(document.service.id, CLICKHOUSE_OUTCOME_SERVICE_ID);
        assert!(document.service.read_only);
        assert!(!document.service.live_execution);
        assert_eq!(document.provider.id, CLICKHOUSE_OUTCOME_PROVIDER_ID);
        assert!(!document.provider.native);
        assert!(document.provider.https_only);
        assert_eq!(document.consumer.id, CLICKHOUSE_OUTCOME_CONSUMER_ID);
        assert!(!document.consumer.adopts_outcome);
        assert!(!document.consumer.truth_authority);
        assert!(!document.native_claims.connected);
        assert!(!document.native_claims.native_provider);
        assert!(!document.native_claims.first_party_provider);
        assert!(!document.native_claims.durable_receipt);
        assert!(!document.native_claims.adopted_outcome);
        assert!(!document.native_claims.blocked_environment_is_native);
        assert_eq!(CLICKHOUSE_OUTCOME_BLOCKED_ENV, "BLOCKED_ENV");
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::first_party_provider());
        assert!(!Layer1Authority::durable_receipt());
        assert!(!Layer1Authority::adopted_outcome());
        assert!(!Layer1Authority::truth_authority());
    }
}
