//! Layer 1 Box governed artifact-result capability.
//!
//! The crate is an independent workspace root by design. It exposes typed
//! metadata, folder pagination, version and bounded-content reads, plus a
//! Mission-scoped non-mutating adoption proposal. The only external transport
//! method surface is authenticated GET; all Box mutations and durable
//! readback remain Layer 2 gaps.

#![deny(unsafe_code)]

mod consumer;
mod error;
mod model;
mod provider;
mod service;
mod transport;

pub use consumer::MissionArtifactResultConsumer;
pub use error::{BoxArtifactError, BoxTransportError};
pub use model::{
    ArtifactAdoptionProposal, ArtifactAvailability, ArtifactCursor, ArtifactProposalRequest,
    ArtifactProposalStatus, ArtifactRevisionFence, BoxArtifactPluginRegistration, BoxArtifactScope,
    BoxAuthMethod, BoxContentResponse, BoxFileMetadata, BoxFileRecord, BoxFileVersion,
    BoxFolderItemsPage, BoxFolderMetadata, BoxFolderRecord, BoxProviderProbe, BoxUserMetadata,
    BoxUserRecord, BoxVersionPage, BoxVersionRecord, ByteRange, ContentDigest,
    ContentReadProjection, ContentReadRequest, CursorKind, EnterpriseId, FileId, FileReadRequest,
    FolderId, FolderItemsProjection, FolderItemsRequest, FolderReadProjection, MAX_CONTENT_BYTES,
    MAX_PAGE_SIZE, MAX_PAGES, MAX_RESPONSE_BYTES, MissionArtifactResult,
    MissionArtifactResultStatus, MissionId, MissionResultBinding, ProbeStatus, ProjectId,
    ProviderProvenance, RegistrationRevocation, ResultId, SecretReference, Sha1Digest, UserId,
    UserReadProjection, VersionId, VersionPageProjection, VersionReadRequest,
};
pub use provider::{
    BOX_ARTIFACT_NATIVE_GATE_ENVIRONMENT_VARIABLE, BOX_ARTIFACT_TOKEN_ENVIRONMENT_VARIABLE,
    BlockedEnvCredentialResolver, BoxArtifactProvider, BoxCredentialResolver, BoxProviderState,
    EnvironmentBoxCredentialResolver, StaticBoxCredentialResolver,
};
pub use service::{
    BoxArtifactProposal, BoxArtifactService, BoxArtifactServiceDefinition,
    BoxArtifactServiceOperation,
};
pub use transport::{
    BoxArtifactFixture, BoxArtifactTransport, BoxTransportOperation, FixtureBoxArtifactTransport,
    FixtureFileFailure, SecretMaterial, UreqBoxArtifactTransport,
};

pub const BOX_ARTIFACT_SCHEMA_VERSION: &str = "hartevo-box-artifact-plugin-contract/v1";
pub const BOX_ARTIFACT_CONTRACT_VERSION: &str = "EXT-BOX-01-L1/v1";
pub const BOX_ARTIFACT_PLUGIN_ID: &str = "hartevo.box-artifact";
pub const BOX_ARTIFACT_PLUGIN_VERSION: u64 = 1;
pub const BOX_ARTIFACT_PROVIDER_ID: &str = "box-artifact";
pub const BOX_ARTIFACT_PROVIDER_VERSION: u64 = 1;
pub const BOX_ARTIFACT_SERVICE_ID: &str = "BoxArtifactService";
pub const BOX_ARTIFACT_MISSION_CONSUMER_ID: &str = "MissionArtifactResultConsumer";
pub const BOX_API_BASE_URL: &str = "https://api.box.com/2.0";
pub const BOX_ARTIFACT_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/box-artifact/box-artifact.v1.json");

pub fn contract_digest() -> ContentDigest {
    ContentDigest::from_bytes(BOX_ARTIFACT_CONTRACT_JSON.as_bytes())
}

/// Layer 1 has no Store, keyring, browser-profile, Effect, or external-write
/// authority. A result is a proposal only; native Connected evidence is not a
/// status that this crate can emit.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReadOnlyAuthority;

impl ReadOnlyAuthority {
    pub const fn external_write() -> bool {
        false
    }

    pub const fn store() -> bool {
        false
    }

    pub const fn keyring() -> bool {
        false
    }

    pub const fn browser_profile() -> bool {
        false
    }

    pub const fn effect() -> bool {
        false
    }

    pub const fn native_connected() -> bool {
        false
    }
}

#[cfg(test)]
mod contract_tests {
    use serde_json::Value;

    use super::{
        BOX_ARTIFACT_CONTRACT_JSON, BOX_ARTIFACT_CONTRACT_VERSION, BOX_ARTIFACT_SCHEMA_VERSION,
        BoxArtifactServiceDefinition, ReadOnlyAuthority, contract_digest,
    };

    #[test]
    fn contract_is_versioned_read_only_and_has_no_native_connected_claim() {
        let document: Value =
            serde_json::from_str(BOX_ARTIFACT_CONTRACT_JSON).expect("Box contract JSON");
        assert_eq!(document["schemaVersion"], BOX_ARTIFACT_SCHEMA_VERSION);
        assert_eq!(document["contractVersion"], BOX_ARTIFACT_CONTRACT_VERSION);
        assert_eq!(document["layer"], 1);
        assert_eq!(document["provider"]["readOnly"], true);
        assert_eq!(document["provider"]["externalWrites"], false);
        assert_eq!(document["consumer"]["durableReadback"], false);
        assert_eq!(document["nativeBoundary"]["nativeConnectedClaim"], false);
        assert_eq!(document["nativeBoundary"]["loopbackIsNative"], false);
        assert_eq!(document["nativeBoundary"]["fixtureIsNative"], false);
        assert_eq!(document["nativeBoundary"]["blockedEnvIsConnected"], false);
        assert!(!ReadOnlyAuthority::external_write());
        assert!(!ReadOnlyAuthority::store());
        assert!(!ReadOnlyAuthority::keyring());
        assert!(!ReadOnlyAuthority::browser_profile());
        assert!(!ReadOnlyAuthority::effect());
        assert!(!ReadOnlyAuthority::native_connected());
        assert_eq!(contract_digest().as_str().len(), 64);
    }

    #[test]
    fn service_definition_is_complete_and_read_only() {
        let definition = BoxArtifactServiceDefinition::layer1();
        definition.validate().expect("valid definition");
        assert_eq!(definition.operations.len(), 8);
        assert!(definition.read_only);
        assert!(!definition.external_writes);
        assert!(!definition.durable_readback);
    }
}
