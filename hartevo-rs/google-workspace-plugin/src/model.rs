use std::collections::BTreeSet;
use std::fmt;
use std::fmt::Write as _;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::GoogleWorkspaceError;

macro_rules! identifier_type {
    ($name:ident, $label:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, GoogleWorkspaceError> {
                let value = value.into();
                validate_identifier(&value, $label)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = GoogleWorkspaceError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }
    };
}

identifier_type!(DriveId, "Drive ID");
identifier_type!(FolderId, "folder ID");
identifier_type!(GoogleFileId, "Google file ID");
identifier_type!(DocumentId, "document ID");

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum ChangeCorpus {
    User,
    SharedDrive { drive_id: DriveId },
}

impl ChangeCorpus {
    pub fn label(&self) -> String {
        match self {
            Self::User => String::from("user"),
            Self::SharedDrive { drive_id } => format!("shared-drive:{drive_id}"),
        }
    }

    pub const fn drive_id(&self) -> Option<&DriveId> {
        match self {
            Self::User => None,
            Self::SharedDrive { drive_id } => Some(drive_id),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChangeScope {
    pub corpus: ChangeCorpus,
    pub folder_id: Option<FolderId>,
}

impl ChangeScope {
    pub fn user(folder_id: Option<FolderId>) -> Self {
        Self {
            corpus: ChangeCorpus::User,
            folder_id,
        }
    }

    pub fn shared_drive(drive_id: DriveId, folder_id: Option<FolderId>) -> Self {
        Self {
            corpus: ChangeCorpus::SharedDrive { drive_id },
            folder_id,
        }
    }

    pub fn validate(&self) -> Result<(), GoogleWorkspaceError> {
        if let Some(folder_id) = &self.folder_id {
            validate_identifier(folder_id.as_str(), "folder ID")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkspaceProbeRequest {
    pub scope: ChangeScope,
    pub document_id: Option<DocumentId>,
}

impl WorkspaceProbeRequest {
    pub fn new(
        scope: ChangeScope,
        document_id: Option<DocumentId>,
    ) -> Result<Self, GoogleWorkspaceError> {
        scope.validate()?;
        Ok(Self { scope, document_id })
    }

    pub fn user(
        folder_id: Option<FolderId>,
        document_id: Option<DocumentId>,
    ) -> Result<Self, GoogleWorkspaceError> {
        Self::new(ChangeScope::user(folder_id), document_id)
    }

    pub fn shared_drive(
        drive_id: DriveId,
        folder_id: Option<FolderId>,
        document_id: Option<DocumentId>,
    ) -> Result<Self, GoogleWorkspaceError> {
        Self::new(ChangeScope::shared_drive(drive_id, folder_id), document_id)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    NativeHttps,
    Loopback,
    Fixture,
    Injected,
}

impl EvidenceSource {
    pub const fn is_connected(&self) -> bool {
        matches!(self, Self::NativeHttps)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeStatus {
    Connected,
    VerifiedLoopbackNotConnected,
    VerifiedFixtureNotConnected,
    VerifiedInjectedNotConnected,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OAuthScopeReceipt {
    pub granted_scopes: BTreeSet<String>,
    pub required_scopes: BTreeSet<String>,
    pub expires_in_seconds: u64,
    pub audience: Option<String>,
    pub token_digest: String,
}

impl OAuthScopeReceipt {
    pub fn has_required_scopes(&self) -> bool {
        self.required_scopes.is_subset(&self.granted_scopes)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GoogleUser {
    pub permission_id: Option<String>,
    pub display_name: Option<String>,
    pub email_address: Option<String>,
    pub photo_link: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SharedDriveMetadata {
    pub id: DriveId,
    pub name: String,
    pub hidden: bool,
    pub restrictions: Option<serde_json::Value>,
}

pub type DriveMetadata = SharedDriveMetadata;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DriveFileMetadata {
    pub id: GoogleFileId,
    pub name: String,
    pub mime_type: String,
    pub parents: Vec<FolderId>,
    pub drive_id: Option<DriveId>,
    pub trashed: bool,
    pub created_time: Option<String>,
    pub modified_time: Option<String>,
    pub version: Option<String>,
    pub web_view_link: Option<String>,
}

impl DriveFileMetadata {
    pub const GOOGLE_DOC_MIME_TYPE: &'static str = "application/vnd.google-apps.document";
    pub const GOOGLE_FOLDER_MIME_TYPE: &'static str = "application/vnd.google-apps.folder";

    pub fn is_google_doc(&self) -> bool {
        self.mime_type == Self::GOOGLE_DOC_MIME_TYPE
    }

    pub fn is_folder(&self) -> bool {
        self.mime_type == Self::GOOGLE_FOLDER_MIME_TYPE
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum CorpusLocation {
    User { drive_id: Option<DriveId> },
    SharedDrive { drive_id: DriveId },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CanonicalDocumentContent {
    pub text: String,
    pub digest: String,
    pub body_end_index: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocumentContentRead {
    pub document_id: DocumentId,
    pub title: String,
    pub provider_revision: String,
    pub content: CanonicalDocumentContent,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocumentRead {
    pub document_id: DocumentId,
    pub title: String,
    pub metadata: DriveFileMetadata,
    pub provider_revision: String,
    pub content: CanonicalDocumentContent,
    pub location: CorpusLocation,
}

pub type DocumentSnapshot = DocumentRead;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocumentReadRequest {
    pub document_id: DocumentId,
    pub scope: ChangeScope,
}

impl DocumentReadRequest {
    pub fn new(document_id: DocumentId, scope: ChangeScope) -> Result<Self, GoogleWorkspaceError> {
        scope.validate()?;
        Ok(Self { document_id, scope })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocumentRevisionRequest {
    pub document_id: DocumentId,
    pub page_size: u32,
}

impl DocumentRevisionRequest {
    pub fn new(document_id: DocumentId, page_size: u32) -> Result<Self, GoogleWorkspaceError> {
        if !(1..=1000).contains(&page_size) {
            return Err(GoogleWorkspaceError::InvalidInput {
                field: "revision page size",
                reason: String::from("must be between 1 and 1000"),
            });
        }
        Ok(Self {
            document_id,
            page_size,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocumentRevision {
    pub id: String,
    pub modified_time: Option<String>,
    pub keep_forever: bool,
    pub published: bool,
    pub size: Option<u64>,
    pub last_modifying_user: Option<GoogleUser>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocumentRevisionPage {
    pub document_id: DocumentId,
    pub revisions: Vec<DocumentRevision>,
    pub next_page_token: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChangeCursor {
    pub corpus: ChangeCorpus,
    pub page_token: String,
}

impl ChangeCursor {
    pub fn new(
        corpus: ChangeCorpus,
        page_token: impl Into<String>,
    ) -> Result<Self, GoogleWorkspaceError> {
        let page_token = page_token.into();
        if page_token.trim().is_empty() {
            return Err(GoogleWorkspaceError::InvalidInput {
                field: "change page token",
                reason: String::from("must not be empty"),
            });
        }
        Ok(Self { corpus, page_token })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChangePageRequest {
    pub scope: ChangeScope,
    pub cursor: ChangeCursor,
    pub page_size: u32,
}

impl ChangePageRequest {
    pub fn new(
        scope: ChangeScope,
        cursor: ChangeCursor,
        page_size: u32,
    ) -> Result<Self, GoogleWorkspaceError> {
        scope.validate()?;
        if scope.corpus != cursor.corpus {
            return Err(GoogleWorkspaceError::ScopeMismatch);
        }
        if !(1..=1000).contains(&page_size) {
            return Err(GoogleWorkspaceError::InvalidInput {
                field: "change page size",
                reason: String::from("must be between 1 and 1000"),
            });
        }
        Ok(Self {
            scope,
            cursor,
            page_size,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeType {
    File,
    Drive,
    #[serde(other)]
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChangeRecord {
    pub change_id: Option<String>,
    pub file_id: GoogleFileId,
    pub removed: bool,
    pub file: Option<DriveFileMetadata>,
    pub time: Option<String>,
    pub change_type: ChangeType,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeDisposition {
    Current,
    Deleted,
    AccessLost,
    CorpusMoved,
    AmbiguousRemoval,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChangeClassification {
    pub file_id: GoogleFileId,
    pub disposition: ChangeDisposition,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChangePage {
    pub scope: ChangeScope,
    pub entries: Vec<ChangeRecord>,
    pub next_cursor: Option<ChangeCursor>,
    pub new_start_cursor: Option<ChangeCursor>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginScope {
    pub tenant_id: String,
    pub project_id: String,
    pub account_id: String,
    pub corpus: ChangeCorpus,
    pub folder_id: Option<FolderId>,
}

impl PluginScope {
    pub fn new(
        tenant_id: impl Into<String>,
        project_id: impl Into<String>,
        account_id: impl Into<String>,
        corpus: ChangeCorpus,
        folder_id: Option<FolderId>,
    ) -> Result<Self, GoogleWorkspaceError> {
        let scope = Self {
            tenant_id: tenant_id.into(),
            project_id: project_id.into(),
            account_id: account_id.into(),
            corpus,
            folder_id,
        };
        for (field, value) in [
            ("tenant ID", &scope.tenant_id),
            ("project ID", &scope.project_id),
            ("account ID", &scope.account_id),
        ] {
            validate_non_empty(value, field)?;
        }
        Ok(scope)
    }

    pub fn digest(&self) -> String {
        let value = format!(
            "{}\n{}\n{}\n{}\n{}",
            self.tenant_id,
            self.project_id,
            self.account_id,
            self.corpus.label(),
            self.folder_id.as_ref().map_or("", FolderId::as_str)
        );
        sha256_hex(value.as_bytes())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MissionWorkProductSelection {
    pub tenant_id: String,
    pub project_id: String,
    pub mission_id: String,
    pub work_product_id: String,
    pub mission_revision: u64,
    pub work_product_revision: u64,
    pub work_product_digest: String,
    pub title: String,
    pub content: String,
}

impl MissionWorkProductSelection {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant_id: impl Into<String>,
        project_id: impl Into<String>,
        mission_id: impl Into<String>,
        work_product_id: impl Into<String>,
        mission_revision: u64,
        work_product_revision: u64,
        work_product_digest: impl Into<String>,
        title: impl Into<String>,
        content: impl Into<String>,
    ) -> Result<Self, GoogleWorkspaceError> {
        let content = canonicalize_document_text(&content.into());
        let selection = Self {
            tenant_id: tenant_id.into(),
            project_id: project_id.into(),
            mission_id: mission_id.into(),
            work_product_id: work_product_id.into(),
            mission_revision,
            work_product_revision,
            work_product_digest: work_product_digest.into(),
            title: title.into(),
            content,
        };
        selection.validate()
    }

    pub fn validate(self) -> Result<Self, GoogleWorkspaceError> {
        for (field, value) in [
            ("tenant ID", &self.tenant_id),
            ("project ID", &self.project_id),
            ("Mission ID", &self.mission_id),
            ("Work Product ID", &self.work_product_id),
            ("title", &self.title),
        ] {
            validate_non_empty(value, field)?;
        }
        if self.mission_revision == 0 || self.work_product_revision == 0 {
            return Err(GoogleWorkspaceError::InvalidInput {
                field: "Work Product revision",
                reason: String::from("Mission and Work Product revisions must be positive"),
            });
        }
        validate_digest(&self.work_product_digest, "Work Product digest")?;
        let content_digest = sha256_hex(self.content.as_bytes());
        if content_digest != self.work_product_digest {
            return Err(GoogleWorkspaceError::InvalidInput {
                field: "Work Product digest",
                reason: format!("does not match canonical content digest {content_digest}"),
            });
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum DocumentAdoptionDestination {
    Create {
        corpus: ChangeCorpus,
        folder_id: Option<FolderId>,
        title: String,
    },
    Update {
        document: Box<DocumentRead>,
        required_provider_revision: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocumentTarget {
    pub operation: AdoptionOperation,
    pub corpus: ChangeCorpus,
    pub folder_id: Option<FolderId>,
    pub document_id: Option<DocumentId>,
    pub title: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdoptionOperation {
    CreateDocument,
    UpdateDocument,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocsLocation {
    pub index: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocsRange {
    pub start_index: u64,
    pub end_index: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocsInsertText {
    pub location: DocsLocation,
    pub text: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocsDeleteContentRange {
    pub range: DocsRange,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum DocsBatchRequest {
    InsertText {
        insert_text: DocsInsertText,
    },
    DeleteContentRange {
        delete_content_range: DocsDeleteContentRange,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocsWriteControl {
    pub required_revision_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocsBatchUpdatePayload {
    pub write_control: Option<DocsWriteControl>,
    pub requests: Vec<DocsBatchRequest>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocumentAdoptionProposal {
    pub schema_version: String,
    pub provider_id: String,
    pub service_id: String,
    pub target: DocumentTarget,
    pub work_product: MissionWorkProductSelection,
    pub required_provider_revision: Option<String>,
    pub canonical_content: String,
    pub canonical_content_digest: String,
    pub batch_update: DocsBatchUpdatePayload,
    pub mutating: bool,
    pub proposal_digest: String,
}

impl DocumentAdoptionProposal {
    pub fn is_non_mutating(&self) -> bool {
        !self.mutating
    }

    pub fn validate(&self) -> Result<(), GoogleWorkspaceError> {
        if self.schema_version != crate::GOOGLE_WORKSPACE_SCHEMA_VERSION
            || self.provider_id != crate::GOOGLE_WORKSPACE_PROVIDER_ID
            || self.service_id != crate::GOOGLE_WORKSPACE_SERVICE_ID
            || self.mutating
        {
            return Err(GoogleWorkspaceError::InvalidInput {
                field: "adoption proposal",
                reason: String::from("provider, service, schema, or read-only boundary mismatch"),
            });
        }
        self.work_product.clone().validate()?;
        let expected_content = canonicalize_document_text(&self.canonical_content);
        if expected_content != self.work_product.content
            || sha256_hex(expected_content.as_bytes()) != self.canonical_content_digest
        {
            return Err(GoogleWorkspaceError::InvalidInput {
                field: "adoption proposal content",
                reason: String::from("content is not the selected Work Product content"),
            });
        }
        if matches!(self.target.operation, AdoptionOperation::UpdateDocument)
            && self.required_provider_revision.is_none()
        {
            return Err(GoogleWorkspaceError::InvalidInput {
                field: "required provider revision",
                reason: String::from("updates must carry a Docs revision fence"),
            });
        }
        if self.proposal_digest != proposal_digest(self)? {
            return Err(GoogleWorkspaceError::InvalidInput {
                field: "proposal digest",
                reason: String::from("does not match canonical proposal fields"),
            });
        }
        Ok(())
    }

    pub(crate) fn with_digest(mut self) -> Result<Self, GoogleWorkspaceError> {
        self.proposal_digest.clear();
        self.proposal_digest = proposal_digest(&self)?;
        Ok(self)
    }
}

fn proposal_digest(proposal: &DocumentAdoptionProposal) -> Result<String, GoogleWorkspaceError> {
    let mut unsigned = proposal.clone();
    unsigned.proposal_digest.clear();
    let bytes =
        serde_json::to_vec(&unsigned).map_err(|error| GoogleWorkspaceError::InvalidInput {
            field: "adoption proposal",
            reason: error.to_string(),
        })?;
    Ok(sha256_hex(&bytes))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkspaceProbeResult {
    pub status: ProbeStatus,
    pub evidence_source: EvidenceSource,
    pub oauth: OAuthScopeReceipt,
    pub user: GoogleUser,
    pub corpus: ChangeScope,
    pub shared_drive: Option<SharedDriveMetadata>,
    pub folder: Option<DriveFileMetadata>,
    pub document: Option<DocumentRead>,
    pub initial_change_cursor: ChangeCursor,
}

pub(crate) fn canonicalize_document_text(value: &str) -> String {
    value.replace("\r\n", "\n").replace('\r', "\n")
}

pub(crate) fn sha256_hex(value: &[u8]) -> String {
    let digest = Sha256::digest(value);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

pub(crate) fn validate_digest(
    value: &str,
    field: &'static str,
) -> Result<(), GoogleWorkspaceError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(GoogleWorkspaceError::InvalidInput {
            field,
            reason: String::from("must be a lowercase or uppercase SHA-256 hex digest"),
        });
    }
    Ok(())
}

pub(crate) fn validate_non_empty(
    value: &str,
    field: &'static str,
) -> Result<(), GoogleWorkspaceError> {
    if value.trim().is_empty() {
        return Err(GoogleWorkspaceError::InvalidInput {
            field,
            reason: String::from("must not be empty"),
        });
    }
    Ok(())
}

pub(crate) fn validate_identifier(
    value: &str,
    field: &'static str,
) -> Result<(), GoogleWorkspaceError> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(GoogleWorkspaceError::InvalidInput {
            field,
            reason: String::from("must be 1-256 ASCII letters, digits, '.', '-' or '_'"),
        });
    }
    Ok(())
}
