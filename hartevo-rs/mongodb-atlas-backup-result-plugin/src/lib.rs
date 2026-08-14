//! Layer-1 governed MongoDB Atlas backup and cluster-health evidence.
//!
//! The crate is intentionally standalone. It models bounded Atlas Admin API
//! v2 read seams, deterministic recording/fixture/loopback transports, and a
//! Mission consumer for a digest-fenced recovery-readiness proposal. It does
//! not resolve native credentials, read database documents, execute queries,
//! create/delete/restore anything, mint a native receipt, or adopt a Hartevo
//! Outcome.

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
    clippy::missing_panics_doc,
    clippy::return_self_not_must_use,
    clippy::type_complexity,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

mod consumer;
mod model;
mod provider;
mod service;

pub use consumer::{
    ConsumerRegistration, MissionConsumerError, MissionMongoDbAtlasConsumer,
    MissionMongoDbAtlasResult, MissionResultState,
};
pub use model::{
    AdoptionAvailability, AtlasCapability, CapabilityKind, CapabilitySet, Cluster, ClusterHealth,
    ClusterMetadata, ClusterName, ConsentId, ConsentScope, ConsumerId, Digest, EvidenceDigests,
    MeasurementGranularity, MeasurementPoint, MeasurementSeries, MeasurementWindow, Mission,
    MissionId, ModelError, MongoDbAtlasRegistration, MongoDbAtlasScope, OrganizationId, Process,
    ProcessEvidenceState, ProcessId, Project, ProjectId, ProviderFence, ProviderId, ProviderMode,
    ReadinessState, RegistrationState, RestoreVerification, Revision, SecretReference, Snapshot,
    SnapshotStatus,
};
pub use provider::{
    ATLAS_ADMIN_API_VERSION, AtlasOperation, AtlasRequestReceipt, AtlasResultReceipt,
    BackupSnapshotPage, BlockedEnvTransport, CLUSTER_METADATA_OPERATION_PATH,
    ClusterMetadataResponse, FixtureTransport, GetClusterMetadataRequest,
    GetProcessMeasurementsRequest, ListBackupSnapshotsRequest, LoopbackTransport,
    MongoDbAtlasProvider, MongoDbAtlasProviderDefinition, MongoDbAtlasTransport,
    PROCESS_MEASUREMENTS_OPERATION_PATH, ProcessMeasurementsResponse, RecordingTransport,
    SNAPSHOT_OPERATION_PATH, TransportError,
};
pub use service::{
    EffectAuthority, EffectError, EffectKind, Layer1Authority, Layer1EffectBoundary,
    Layer1ReadBackBoundary, MeasurementEvidence, MongoDbAtlasBackupResultService,
    MongoDbAtlasBackupResultServiceDefinition, MongoDbAtlasBackupResultServiceError, PartialReason,
    ReadBackError, ReadBackRecord, Receipt, ReceiptKind, ReceiptReadBack, RecoveryEffectRequest,
    RecoveryReadinessEvidence, RecoveryReadinessProposal, RecoveryReadinessRequest, RetryEvidence,
    RetryPolicy, SnapshotEvidence,
};

pub const MONGODB_ATLAS_BACKUP_RESULT_SCHEMA_VERSION: &str =
    "hartevo-mongodb-atlas-backup-result-contract/v1";
pub const MONGODB_ATLAS_BACKUP_RESULT_CONTRACT_VERSION: &str = "mongodb-atlas-backup-result-e1/v1";
pub const MONGODB_ATLAS_BACKUP_RESULT_SERVICE_ID: &str = "mongodb.atlas.backup-result";
pub const MONGODB_ATLAS_BACKUP_RESULT_SERVICE_VERSION: &str = "1.0.0";
pub const MONGODB_ATLAS_BACKUP_RESULT_PROVIDER_ID: &str = "mongodb-atlas.backup-health.v2";
pub const MONGODB_ATLAS_BACKUP_RESULT_CONSUMER_ID: &str =
    "mission.mongodb-atlas.backup-result.consumer";
pub const MONGODB_ATLAS_BACKUP_RESULT_EVIDENCE_LEVEL: &str = "E1";
pub const MONGODB_ATLAS_BACKUP_RESULT_BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const MONGODB_ATLAS_BACKUP_RESULT_CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/mongodb-atlas-backup-result/mongodb-atlas-backup-result.v1.json"
);

#[cfg(test)]
mod contract_document_tests {
    use serde_json::Value;

    use super::{
        MONGODB_ATLAS_BACKUP_RESULT_BLOCKED_ENV, MONGODB_ATLAS_BACKUP_RESULT_CONSUMER_ID,
        MONGODB_ATLAS_BACKUP_RESULT_CONTRACT_JSON, MONGODB_ATLAS_BACKUP_RESULT_CONTRACT_VERSION,
        MONGODB_ATLAS_BACKUP_RESULT_EVIDENCE_LEVEL, MONGODB_ATLAS_BACKUP_RESULT_PROVIDER_ID,
        MONGODB_ATLAS_BACKUP_RESULT_SCHEMA_VERSION, MONGODB_ATLAS_BACKUP_RESULT_SERVICE_ID,
    };

    #[test]
    fn embedded_contract_is_layer_one_and_honest() {
        let contract = serde_json::from_str::<Value>(MONGODB_ATLAS_BACKUP_RESULT_CONTRACT_JSON)
            .expect("MongoDB Atlas contract JSON");
        assert_eq!(
            contract["schemaVersion"],
            MONGODB_ATLAS_BACKUP_RESULT_SCHEMA_VERSION
        );
        assert_eq!(
            contract["contractVersion"],
            MONGODB_ATLAS_BACKUP_RESULT_CONTRACT_VERSION
        );
        assert_eq!(
            contract["evidenceLevel"],
            MONGODB_ATLAS_BACKUP_RESULT_EVIDENCE_LEVEL
        );
        assert_eq!(contract["layer"], 1);
        assert_eq!(
            contract["service"]["id"],
            MONGODB_ATLAS_BACKUP_RESULT_SERVICE_ID
        );
        assert_eq!(
            contract["provider"]["id"],
            MONGODB_ATLAS_BACKUP_RESULT_PROVIDER_ID
        );
        assert_eq!(
            contract["consumer"]["id"],
            MONGODB_ATLAS_BACKUP_RESULT_CONSUMER_ID
        );
        assert!(
            contract["service"]["readOnly"]
                .as_bool()
                .is_some_and(|value| value)
        );
        assert!(
            !contract["service"]["liveExecution"]
                .as_bool()
                .is_some_and(|value| value)
        );
        assert!(
            !contract["provider"]["native"]
                .as_bool()
                .is_some_and(|value| value)
        );
        assert!(
            !contract["provider"]["connected"]
                .as_bool()
                .is_some_and(|value| value)
        );
        assert!(
            !contract["nativeClaims"]["restoreAuthority"]
                .as_bool()
                .is_some_and(|value| value)
        );
        assert_eq!(MONGODB_ATLAS_BACKUP_RESULT_BLOCKED_ENV, "BLOCKED_ENV");
    }
}
