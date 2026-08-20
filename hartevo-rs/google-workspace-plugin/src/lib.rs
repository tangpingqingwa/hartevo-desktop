//! Layer 1 Google Drive and Google Docs result-workspace capability.
//!
//! This crate is intentionally independent from the Hartevo workspace.  It
//! owns a typed service definition, a Google provider, and the narrow Mission
//! consumer that turns a selected Work Product into a non-mutating adoption
//! proposal.  Every provider call in Layer 1 is an authenticated `GET`; the
//! proposal contains the future Docs write-control payload but never sends it.

mod consumer;
mod error;
mod http;
mod model;
mod provider;
mod registration;

pub use consumer::{MissionAdoptionRequest, MissionResultWorkspaceConsumer};
pub use error::GoogleWorkspaceError;
pub use http::{
    HttpMethod, HttpRequest, HttpResponse, HttpTransport, ReqwestTransport, TransportError,
};
pub use model::{
    AdoptionOperation, CanonicalDocumentContent, ChangeClassification, ChangeCorpus, ChangeCursor,
    ChangeDisposition, ChangePage, ChangePageRequest, ChangeRecord, ChangeScope, ChangeType,
    CorpusLocation, DocsBatchRequest, DocsBatchUpdatePayload, DocsDeleteContentRange,
    DocsInsertText, DocsLocation, DocsRange, DocsWriteControl, DocumentAdoptionDestination,
    DocumentAdoptionProposal, DocumentContentRead, DocumentId, DocumentRead, DocumentReadRequest,
    DocumentRevision, DocumentRevisionPage, DocumentRevisionRequest, DocumentSnapshot,
    DocumentTarget, DriveFileMetadata, DriveId, DriveMetadata, EvidenceSource, FolderId,
    GoogleFileId, GoogleUser, MissionWorkProductSelection, OAuthScopeReceipt, PluginScope,
    ProbeStatus, SharedDriveMetadata, WorkspaceProbeRequest, WorkspaceProbeResult,
};
pub use provider::{
    AccessToken, ApiEndpoints, GoogleDriveDocsProvider, ProbeOutcome, ResultWorkspaceService,
};
pub use registration::{GoogleWorkspacePluginRegistration, RegistrationRevocation};

pub const GOOGLE_WORKSPACE_SCHEMA_VERSION: &str = "hartevo-google-workspace-result/v1";
pub const GOOGLE_WORKSPACE_CONTRACT_VERSION: &str = "EXT-GWS-01-L1/v1";
pub const GOOGLE_WORKSPACE_PLUGIN_ID: &str = "google-workspace.result-workspace";
pub const GOOGLE_WORKSPACE_PROVIDER_ID: &str = "google-drive-docs";
pub const GOOGLE_WORKSPACE_SERVICE_ID: &str = "result-workspace";
pub const GOOGLE_WORKSPACE_MISSION_CONSUMER_ID: &str = "mission.result-workspace.adoption";
pub const GOOGLE_WORKSPACE_ADAPTER_ID: &str = "google-workspace.result-workspace.read";
pub const GOOGLE_WORKSPACE_PLUGIN_VERSION: u64 = 1;
pub const GOOGLE_WORKSPACE_ACCESS_TOKEN_ENV: &str = "HARTEVO_GOOGLE_WORKSPACE_ACCESS_TOKEN";
pub const GOOGLE_OAUTH_TOKENINFO_URL: &str = "https://oauth2.googleapis.com/tokeninfo";
pub const GOOGLE_DRIVE_API_BASE_URL: &str = "https://www.googleapis.com/drive/v3/";
pub const GOOGLE_DOCS_API_BASE_URL: &str = "https://docs.googleapis.com/v1/";
pub const GOOGLE_DRIVE_METADATA_READ_SCOPE: &str =
    "https://www.googleapis.com/auth/drive.metadata.readonly";
pub const GOOGLE_DOCS_READ_SCOPE: &str = "https://www.googleapis.com/auth/documents.readonly";
pub const GOOGLE_WORKSPACE_CONTRACT_JSON: &str =
    include_str!("../../../contracts/plugins/google-workspace/result-workspace.v1.json");

/// The required OAuth scopes for every native probe.
pub const REQUIRED_OAUTH_SCOPES: [&str; 2] =
    [GOOGLE_DRIVE_METADATA_READ_SCOPE, GOOGLE_DOCS_READ_SCOPE];

/// Layer 1 has no external write, Store, keyring, Browser Profile, or Effect
/// authority.  Native OAuth can still report a truthful provider probe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
}

#[cfg(test)]
mod contract_tests {
    use serde_json::Value;

    use super::{
        GOOGLE_WORKSPACE_CONTRACT_JSON, GOOGLE_WORKSPACE_CONTRACT_VERSION,
        GOOGLE_WORKSPACE_SCHEMA_VERSION, REQUIRED_OAUTH_SCOPES, ReadOnlyAuthority,
    };

    #[test]
    fn layer_one_contract_is_read_only_and_has_exact_oauth_scopes() {
        let document: Value = serde_json::from_str(GOOGLE_WORKSPACE_CONTRACT_JSON)
            .expect("Google Workspace contract JSON");
        assert_eq!(document["schemaVersion"], GOOGLE_WORKSPACE_SCHEMA_VERSION);
        assert_eq!(
            document["contractVersion"],
            GOOGLE_WORKSPACE_CONTRACT_VERSION
        );
        assert_eq!(document["layer"], 1);
        assert_eq!(
            document["oauth"]["requiredScopes"][0],
            REQUIRED_OAUTH_SCOPES[0]
        );
        assert_eq!(
            document["oauth"]["requiredScopes"][1],
            REQUIRED_OAUTH_SCOPES[1]
        );
        assert_eq!(document["authority"]["externalWrite"], false);
        assert_eq!(document["authority"]["storeAuthority"], false);
        assert_eq!(document["authority"]["keyringAuthority"], false);
        assert_eq!(document["authority"]["browserProfileAuthority"], false);
        assert_eq!(document["adoptionProposal"]["mutating"], false);
        assert!(!ReadOnlyAuthority::external_write());
        assert!(!ReadOnlyAuthority::store());
        assert!(!ReadOnlyAuthority::keyring());
        assert!(!ReadOnlyAuthority::browser_profile());
        assert!(!ReadOnlyAuthority::effect());
    }
}
