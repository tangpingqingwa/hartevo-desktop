//! Layer-1 governed AWS Cost Explorer spend-evidence plugin.
//!
//! This crate is intentionally standalone. It compiles bounded
//! GetCostAndUsage, GetUsageForecast, and GetDimensionValues proposals,
//! and can compile GetCostAndUsageWithResources only when a caller supplies
//! an explicit operation allowlist and a ResourceId bound. It never performs a
//! native AWS request, stores credentials, mutates billing state, adopts an
//! Outcome, or claims Connected/native authority.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::struct_field_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

mod consumer;
mod model;
mod provider;
mod service;

pub use consumer::{
    ConsumerError, ConsumerRegistration, MissionAwsCostConsumer, MissionAwsCostDecision,
    MissionAwsCostProposal, NextMissionStep,
};
pub use model::{
    AccountId, AwsAccountBinding, AwsCostExplorerRegistration, AwsCostExplorerScope, AwsOperation,
    AwsRegion, BillingViewArn, CostControlObjective, CostFilter, CostMetric, Date, Digest,
    DimensionKey, DimensionValue, EvidenceBounds, EvidenceState, FilterClause, ForecastHorizon,
    Granularity, GroupDefinition, MatchOption, MetricMap, MetricValue, MissionId, ModelError,
    NormalizedAmount, ObjectiveId, OpaqueNextPageToken, PartialReason, PermissionFence,
    PermissionId, PermissionRegistration, ProjectId, ProviderErrorEvidence, ProviderErrorKind,
    RegistrationRevocation, Revision, SecretReference, TagKey, TimePeriod, WorkProductId,
    normalize_grouping, normalize_metrics,
};
pub use provider::{
    AwsCostExplorerProvider, AwsCostExplorerProviderDefinition, AwsCostExplorerTransport,
    BlockedEnvAwsCostExplorerTransport, BlockedEnvTransport, CostAndUsageRequest,
    CostExplorerProvider, CostGroup, CostResultByTime, CostUsagePage, DimensionValuesPage,
    DimensionValuesRequest, EvidenceBinding, FakeAwsCostExplorerTransport, ForecastPoint,
    LoopbackAwsCostExplorerTransport, ProviderDefinitionError, ProviderProvenance,
    RecordingAwsCostExplorerTransport, TransportError, UsageForecastRequest, UsageForecastResponse,
};
pub use service::{
    AwsCostExplorerOutcomeService, AwsCostExplorerProposal, AwsCostExplorerProposalRequest,
    AwsCostExplorerService, AwsCostExplorerServiceDefinition, AwsCostExplorerServiceError,
    CostUsageEvidence, CostUsageProposal, CostUsageProposalRequest, DimensionValuesEvidence,
    DimensionValuesProposal, DimensionValuesProposalRequest, ForecastEvidence, RetryEvidence,
    UsageForecastProposal, UsageForecastProposalRequest,
};

pub const AWS_COST_EXPLORER_SCHEMA_VERSION: &str = "hartevo-aws-cost-explorer-outcome-contract/v1";
pub const AWS_COST_EXPLORER_CONTRACT_VERSION: &str = "aws-cost-explorer-e1/v1";
pub const AWS_COST_EXPLORER_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/aws-cost-explorer-outcome/aws-cost-explorer-outcome.v1.json"
);
pub const AWS_COST_EXPLORER_SERVICE_ID: &str = "aws.cost-explorer.outcome";
pub const AWS_COST_EXPLORER_PROVIDER_ID: &str = "aws.cost-explorer";
pub const AWS_COST_EXPLORER_CONSUMER_ID: &str = "mission.aws.cost-explorer.consumer";
pub const AWS_COST_EXPLORER_EVIDENCE_LEVEL: &str = "E1";
pub const AWS_COST_EXPLORER_BLOCKED_ENV: &str = "BLOCKED_ENV";

/// Layer 1 never claims AWS connectivity, native execution, or outcome
/// authority. Its output is evidence for a later Mission decision step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    pub const fn connected() -> bool {
        false
    }

    pub const fn native_provider() -> bool {
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
        AWS_COST_EXPLORER_BLOCKED_ENV, AWS_COST_EXPLORER_CONSUMER_ID,
        AWS_COST_EXPLORER_CONTRACT_JSON, AWS_COST_EXPLORER_CONTRACT_VERSION,
        AWS_COST_EXPLORER_EVIDENCE_LEVEL, AWS_COST_EXPLORER_PROVIDER_ID,
        AWS_COST_EXPLORER_SCHEMA_VERSION, AWS_COST_EXPLORER_SERVICE_ID, Layer1Authority,
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
        resource_operation_default: bool,
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
        truth_authority: bool,
        blocked_environment_is_native: bool,
    }

    #[test]
    fn contract_document_keeps_layer_one_honest() {
        let document = serde_json::from_str::<ContractDocument>(AWS_COST_EXPLORER_CONTRACT_JSON)
            .expect("AWS Cost Explorer contract JSON");
        assert_eq!(document.schema_version, AWS_COST_EXPLORER_SCHEMA_VERSION);
        assert_eq!(
            document.contract_version,
            AWS_COST_EXPLORER_CONTRACT_VERSION
        );
        assert_eq!(document.evidence_level, AWS_COST_EXPLORER_EVIDENCE_LEVEL);
        assert_eq!(document.layer, 1);
        assert_eq!(document.service.id, AWS_COST_EXPLORER_SERVICE_ID);
        assert!(document.service.read_only);
        assert!(!document.service.live_execution);
        assert_eq!(document.provider.id, AWS_COST_EXPLORER_PROVIDER_ID);
        assert!(!document.provider.native);
        assert!(!document.provider.resource_operation_default);
        assert_eq!(document.consumer.id, AWS_COST_EXPLORER_CONSUMER_ID);
        assert!(!document.consumer.adopts_outcome);
        assert!(!document.consumer.truth_authority);
        assert!(!document.native_claims.connected);
        assert!(!document.native_claims.native_provider);
        assert!(!document.native_claims.durable_receipt);
        assert!(!document.native_claims.adopted_outcome);
        assert!(!document.native_claims.truth_authority);
        assert!(!document.native_claims.blocked_environment_is_native);
        assert_eq!(AWS_COST_EXPLORER_BLOCKED_ENV, "BLOCKED_ENV");
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native_provider());
        assert!(!Layer1Authority::durable_receipt());
        assert!(!Layer1Authority::adopted_outcome());
        assert!(!Layer1Authority::truth_authority());
    }
}
