//! Standalone Layer-1 governed GCP AlloyDB cluster-result boundary.
//!
//! This crate exposes only bounded `clusters.get` and
//! `clusters.instances.get` evidence for one exact target revision. It has no
//! native GCP transport, credential resolver, database data-plane, mutation,
//! or Hartevo kernel authority. Fixture, recording, fake, loopback, and
//! `BLOCKED_ENV` provenance are always non-connected, non-native, and
//! non-first-party.

#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::if_not_else,
    clippy::manual_let_else,
    clippy::match_same_arms,
    clippy::missing_fields_in_debug,
    clippy::module_name_repetitions,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::struct_excessive_bools,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps
)]

pub mod consumer;
pub mod model;
pub mod provider;
pub mod service;

pub use consumer::{
    ConsumerError, MissionGcpAlloyDbClusterConsumer, MissionGcpAlloyDbClusterResult,
};
pub use model::*;
pub use provider::{
    BlockedEnvTransport, FakeGcpAlloyDbTransport, FakeTransport, FixtureGcpAlloyDbTransport,
    FixtureTransport, GcpAlloyDbAdminProvider, GcpAlloyDbProviderDefinition, GcpAlloyDbTransport,
    GetClusterRequest, GetClusterResponse, GetInstanceRequest, GetInstanceResponse,
    LoopbackGcpAlloyDbTransport, LoopbackTransport, ProviderDefinitionError, ProviderError,
    ProviderRequestReceipt, RecordingGcpAlloyDbTransport, RecordingTransport, TransportCall,
    TransportError,
};
pub use service::{
    ContractDocumentError, GcpAlloyDbCapabilities, GcpAlloyDbClusterResultContract,
    GcpAlloyDbClusterResultProposal, GcpAlloyDbClusterResultService, GcpAlloyDbReadRequest,
    GcpAlloyDbReadResult, GcpAlloyDbRecordReceipt, GcpAlloyDbRegistration, GcpAlloyDbService,
    GcpAlloyDbVerificationReport, RegistrationError, RegistrationState,
    RegistrationTransitionEvidence, ServiceError,
};

pub const SCHEMA_VERSION: &str = "hartevo.gcp-alloydb-cluster-result.contract/v1";
pub const CONTRACT_VERSION: &str = "gcp-alloydb-cluster-result/v1";
pub const PLUGIN_VERSION: &str = "1.0.0";
pub const SERVICE_ID: &str = "hartevo.gcp.alloydb.cluster-result";
pub const GCP_ALLOYDB_PROVIDER_ID: &str = "gcp.alloydb.admin";
pub const GCP_ALLOYDB_PROVIDER_VERSION: &str = "1.0.0";
pub const API_REVISION: &str = "gcp-alloydb-admin-read-r1";
pub const CONSUMER_ID: &str = "mission.gcp.alloydb.cluster-result";
pub const BLOCKED_ENV: &str = "BLOCKED_ENV";
pub const OFFICIAL_CLUSTER_GET: &str =
    "https://docs.cloud.google.com/alloydb/docs/reference/rest/v1/projects.locations.clusters/get";
pub const OFFICIAL_INSTANCE_GET: &str = "https://docs.cloud.google.com/alloydb/docs/reference/rest/v1/projects.locations.clusters.instances/get";
pub const OFFICIAL_REST_REFERENCE: &str =
    "https://docs.cloud.google.com/alloydb/docs/reference/rest";
pub const GCP_ALLOYDB_API_DIGEST_INPUT: &str =
    "gcp-alloydb-admin-read-r1|GET|clusters.get|instances.get|no-pagination|layer1";
pub const CONTRACT_JSON: &str = include_str!(
    "../../../contracts/plugins/gcp-alloydb-cluster-result/gcp-alloydb-cluster-result.v1.json"
);

pub fn contract_digest() -> Digest {
    Digest::from_bytes(CONTRACT_JSON.as_bytes())
}

pub fn evidence_binding_digest() -> Digest {
    Digest::from_parts(
        "gcp-alloydb-evidence-binding/v1",
        &[
            ("schema", SCHEMA_VERSION.to_owned()),
            ("contract", CONTRACT_VERSION.to_owned()),
            (
                "cluster_projection",
                "state,type,availability,database_version,instance_count,revision".to_owned(),
            ),
            (
                "instance_projection",
                "state,type,availability,cpu_count,node_count,revision".to_owned(),
            ),
            (
                "redaction",
                "connection_info,endpoints,credentials,users,sql_rows,raw_bodies".to_owned(),
            ),
        ],
    )
}

pub const fn plugin_version() -> (u16, u16, u16) {
    (1, 0, 0)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layer1Authority;

impl Layer1Authority {
    pub const fn connected() -> bool {
        false
    }

    pub const fn native() -> bool {
        false
    }

    pub const fn first_party() -> bool {
        false
    }

    pub const fn truth() -> bool {
        false
    }

    pub const fn consent() -> bool {
        false
    }

    pub const fn effect() -> bool {
        false
    }

    pub const fn receipt() -> bool {
        false
    }

    pub const fn verification() -> bool {
        false
    }

    pub const fn outcome() -> bool {
        false
    }

    pub const fn durable_provider_receipt() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn contract_is_layer_one_and_authority_is_closed() {
        let contract = GcpAlloyDbClusterResultContract::baseline().expect("contract");
        assert_eq!(contract.value()["schemaVersion"], SCHEMA_VERSION);
        assert_eq!(contract.value()["contractVersion"], CONTRACT_VERSION);
        assert_eq!(contract.value()["pluginVersion"], PLUGIN_VERSION);
        assert_eq!(contract.value()["layer"], "Layer-1");
        assert_eq!(contract.value()["provider"]["apiRevision"], API_REVISION);
        assert_eq!(contract.value()["provider"]["connected"], false);
        assert_eq!(contract.value()["provider"]["native"], false);
        assert_eq!(contract.value()["provider"]["firstParty"], false);
        assert!(!Layer1Authority::connected());
        assert!(!Layer1Authority::native());
        assert!(!Layer1Authority::first_party());
        assert!(!Layer1Authority::truth());
        assert!(!Layer1Authority::consent());
        assert!(!Layer1Authority::effect());
        assert!(!Layer1Authority::receipt());
        assert!(!Layer1Authority::verification());
        assert!(!Layer1Authority::outcome());
        assert!(!Layer1Authority::durable_provider_receipt());
    }
}
