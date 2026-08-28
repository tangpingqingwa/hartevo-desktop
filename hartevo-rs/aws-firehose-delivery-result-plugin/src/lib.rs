//! Standalone Layer-1 AWS Kinesis Data Firehose delivery-result boundary.
//!
//! The crate owns only bounded `ListDeliveryStreams` and
//! `DescribeDeliveryStream` read/proposal/record/verify seams. It never
//! resolves credentials, performs native SigV4/HTTPS, writes Firehose data,
//! retrieves payloads or delivery logs, mutates a destination, or claims
//! Connected/native/first-party/delivery-completion authority.

#![forbid(unsafe_code)]
#![allow(
    clippy::collapsible_if,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::missing_const_for_fn,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

pub mod consumer;
pub mod error;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    ConsumerError, MissionAwsFirehoseConsumer, MissionAwsFirehoseDecisionState,
    MissionAwsFirehoseDeliveryConsumer, MissionAwsFirehoseDeliveryResult, MissionAwsFirehoseResult,
    RecordedAwsFirehoseResult,
};
pub use error::{AwsFirehoseError, AwsFirehoseTransportError, Result};
pub use model::{
    AwsAccountId, AwsFirehoseDeliveryScope, AwsFirehoseProviderScope, AwsRegion, ConsentScope,
    DeliveryStreamName, DeliveryStreamObservation, DestinationHealth, DestinationId,
    DestinationObservation, DestinationType, Digest, MissionId, MissionIdentity, MissionProjection,
    PermissionSnapshot, ProjectId, ProjectIdentity, ProjectProjection, Revision, SecretReference,
    SecretScheme, StreamStatus, StreamVersionId, TransportProvenance, WorkProductId,
    WorkProductIdentity, WorkProductProjection,
};
pub use provider::{
    AwsFirehoseOperation, AwsFirehoseProvider, AwsFirehoseProviderDefinition,
    AwsFirehoseProviderDefinitionError, AwsFirehoseTransport, BlockedEnvTransport,
    DescribeDeliveryStreamRequest, DescribeDeliveryStreamResponse, FirehoseScopeView,
    FixtureAwsFirehoseTransport, FixtureTransport, ListDeliveryStreamsRequest,
    ListDeliveryStreamsResponse, LoopbackAwsFirehoseTransport, LoopbackTransport,
    OpaqueExclusiveStart, RecordedRequest, RecordingAwsFirehoseTransport, RecordingTransport,
};
pub use service::{
    AwsFirehoseCapabilityDescription, AwsFirehoseDeliveryProposal, AwsFirehoseDeliveryService,
    AwsFirehoseDeliveryServiceDefinition, AwsFirehoseEvidenceState, AwsFirehoseProposal,
    AwsFirehoseReadEvidence, AwsFirehoseReadRequest, AwsFirehoseReadResult,
    AwsFirehoseRegistration, AwsFirehoseService, AwsFirehoseServiceError, CapabilityDescription,
    CostReceipt, DestinationEvidence, FailureEvidence, RedactedResponseReceipt, RegistrationState,
    RegistrationTransition, ServiceError, StreamEvidence, VerificationReport, contract_digest,
};

pub const CONTRACT_SCHEMA: &str = "hartevo.aws-firehose-delivery-result/v1";
pub const CONTRACT_VERSION: &str = "EXT-AWSFIREHOSE-01-L1/v1";
pub const CONTRACT_DIGEST_INPUT: &str = "hartevo.aws-firehose-delivery-result/v1|layer=1|service=aws.firehose.delivery-result.read|provider=aws.firehose.delivery-result.recording|consumer=mission.aws-firehose-delivery.consumer";
pub const CONTRACT_DIGEST: &str =
    "a13e8c18c4fd2bdb5098b094d3ec733933646cd6cc050034a388c7f86844d82e";
pub const CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/aws-firehose-delivery-result/contract.v1.json");
pub const PLUGIN_ID: &str = "aws.firehose.delivery-result";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "aws.firehose.delivery-result.read";
pub const PROVIDER_ID: &str = "aws.firehose.delivery-result.recording";
pub const PROVIDER_VERSION: &str = "1.0.0";
pub const PROVIDER_API_REVISION: &str = "firehose-list-delivery-streams-describe-delivery-stream-1";
pub const API_VERSION: &str = "2015-08-04";
pub const CONSUMER_ID: &str = "mission.aws-firehose-delivery.consumer";
pub const EVIDENCE_LEVEL: &str = "L1_PROVIDER_CONTRACT";
pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_CURSOR_BYTES: usize = 4 * 1024;
pub const MAX_ALLOWLISTED_STREAMS: usize = 16;
pub const MAX_PAGE_SIZE: u16 = 100;
pub const MAX_PAGES: u16 = 4;
pub const MAX_REQUESTS_PER_READ: u16 = 5;
pub const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
pub const LAYER1_PERMISSIONS: [&str; 3] = [
    "firehose:ListDeliveryStreams",
    "firehose:DescribeDeliveryStream",
    "mission.scope",
];

pub const FORBIDDEN_EFFECTS: [&str; 13] = [
    "firehose:PutRecord",
    "firehose:PutRecordBatch",
    "firehose:CreateDeliveryStream",
    "firehose:UpdateDestination",
    "firehose:DeleteDeliveryStream",
    "firehose:TagDeliveryStream",
    "firehose:UntagDeliveryStream",
    "raw_payload_export",
    "raw_s3_object_read",
    "transformation_code_export",
    "destination_mutation",
    "delivery_log_retrieval",
    "outcome.adopt",
];

#[cfg(test)]
mod contract_tests {
    use serde::Deserialize;

    use super::{
        API_VERSION, CONSUMER_ID, CONTRACT_DIGEST, CONTRACT_DIGEST_INPUT, CONTRACT_JSON,
        CONTRACT_SCHEMA, CONTRACT_VERSION, EVIDENCE_LEVEL, PLUGIN_ID, PLUGIN_VERSION,
        PROVIDER_API_REVISION, PROVIDER_ID, PROVIDER_VERSION, SERVICE_ID,
    };

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ContractDocument {
        schema_version: String,
        contract_version: String,
        plugin_id: String,
        plugin_version: String,
        layer: String,
        evidence_level: String,
        digest_input: String,
        contract_digest: String,
        service: ServiceDocument,
        provider: ProviderDocument,
        consumer: ConsumerDocument,
        credentials: CredentialDocument,
        scope: ScopeDocument,
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
        recording_only: bool,
        live_execution: bool,
        external_writes: bool,
        kernel_authority: bool,
        outcome_adoption: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ProviderDocument {
        id: String,
        version: String,
        api_version: String,
        api_revision: String,
        native: bool,
        connected: bool,
        first_party: bool,
        external_writes: bool,
        provider_receipt: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ConsumerDocument {
        id: String,
        implementation: String,
        project_bound: bool,
        mission_bound: bool,
        work_product_bound: bool,
        revision_bound: bool,
        provider_scope_bound: bool,
        permission_bound: bool,
        adopts_outcome: bool,
        adopts_work_product: bool,
        truth_authority: bool,
        verification_authority: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct CredentialDocument {
        serialized: bool,
        debug_redacted: bool,
        raw_material_accepted: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ScopeDocument {
        stream_allowlist_required: bool,
        raw_payload_bytes: bool,
        raw_destination_configuration: bool,
        raw_s3_objects: bool,
        transformation_code: bool,
        raw_secrets: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AuthorityDocument {
        read_only: bool,
        proposal_only: bool,
        recording_only: bool,
        external_writes: bool,
        connected: bool,
        native: bool,
        first_party: bool,
        durable_receipt: bool,
        truth_authority: bool,
        kernel_outcome_adoption: bool,
        work_product_adoption: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct HonestyDocument {
        blocked_environment_is_native: bool,
        fixture_is_native: bool,
        recording_is_native: bool,
        loopback_is_native: bool,
        healthy_destination_is_delivery_proof: bool,
        active_stream_is_delivery_proof: bool,
    }

    #[test]
    fn checked_contract_is_versioned_layer_one_and_non_native() {
        let document =
            serde_json::from_str::<ContractDocument>(CONTRACT_JSON).expect("Firehose contract");
        assert_eq!(document.schema_version, CONTRACT_SCHEMA);
        assert_eq!(document.contract_version, CONTRACT_VERSION);
        assert_eq!(document.plugin_id, PLUGIN_ID);
        assert_eq!(document.plugin_version, PLUGIN_VERSION);
        assert_eq!(document.layer, "Layer-1");
        assert_eq!(document.evidence_level, EVIDENCE_LEVEL);
        assert_eq!(document.digest_input, CONTRACT_DIGEST_INPUT);
        assert_eq!(document.contract_digest, CONTRACT_DIGEST);
        assert_eq!(document.service.id, SERVICE_ID);
        assert_eq!(
            document.service.implementation,
            "AwsFirehoseDeliveryService"
        );
        assert!(document.service.read_only);
        assert!(document.service.proposal_only);
        assert!(document.service.recording_only);
        assert!(!document.service.live_execution);
        assert!(!document.service.external_writes);
        assert!(!document.service.kernel_authority);
        assert!(!document.service.outcome_adoption);
        assert_eq!(document.provider.id, PROVIDER_ID);
        assert_eq!(document.provider.version, PROVIDER_VERSION);
        assert_eq!(document.provider.api_version, API_VERSION);
        assert_eq!(document.provider.api_revision, PROVIDER_API_REVISION);
        assert!(!document.provider.native);
        assert!(!document.provider.connected);
        assert!(!document.provider.first_party);
        assert!(!document.provider.external_writes);
        assert!(!document.provider.provider_receipt);
        assert_eq!(document.consumer.id, CONSUMER_ID);
        assert_eq!(
            document.consumer.implementation,
            "MissionAwsFirehoseConsumer"
        );
        assert!(document.consumer.project_bound);
        assert!(document.consumer.mission_bound);
        assert!(document.consumer.work_product_bound);
        assert!(document.consumer.revision_bound);
        assert!(document.consumer.provider_scope_bound);
        assert!(document.consumer.permission_bound);
        assert!(!document.consumer.adopts_outcome);
        assert!(!document.consumer.adopts_work_product);
        assert!(!document.consumer.truth_authority);
        assert!(!document.consumer.verification_authority);
        assert!(!document.credentials.serialized);
        assert!(document.credentials.debug_redacted);
        assert!(!document.credentials.raw_material_accepted);
        assert!(document.scope.stream_allowlist_required);
        assert!(!document.scope.raw_payload_bytes);
        assert!(!document.scope.raw_destination_configuration);
        assert!(!document.scope.raw_s3_objects);
        assert!(!document.scope.transformation_code);
        assert!(!document.scope.raw_secrets);
        assert!(document.authority.read_only);
        assert!(document.authority.proposal_only);
        assert!(document.authority.recording_only);
        assert!(!document.authority.external_writes);
        assert!(!document.authority.connected);
        assert!(!document.authority.native);
        assert!(!document.authority.first_party);
        assert!(!document.authority.durable_receipt);
        assert!(!document.authority.truth_authority);
        assert!(!document.authority.kernel_outcome_adoption);
        assert!(!document.authority.work_product_adoption);
        assert!(!document.honesty.blocked_environment_is_native);
        assert!(!document.honesty.fixture_is_native);
        assert!(!document.honesty.recording_is_native);
        assert!(!document.honesty.loopback_is_native);
        assert!(!document.honesty.healthy_destination_is_delivery_proof);
        assert!(!document.honesty.active_stream_is_delivery_proof);
    }
}
