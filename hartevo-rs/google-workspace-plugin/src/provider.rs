use std::collections::BTreeSet;
use std::env;
use std::fmt;
use std::sync::Arc;

use serde::Deserialize;
use serde_json::Value;
use url::Url;

use crate::error::GoogleWorkspaceError;
use crate::http::{HttpRequest, HttpTransport, ReqwestTransport, TransportError};
use crate::model::{
    AdoptionOperation, CanonicalDocumentContent, ChangeClassification, ChangeCursor,
    ChangeDisposition, ChangePage, ChangePageRequest, ChangeRecord, ChangeScope, ChangeType,
    CorpusLocation, DocsBatchRequest, DocsBatchUpdatePayload, DocsDeleteContentRange,
    DocsInsertText, DocsLocation, DocsRange, DocsWriteControl, DocumentAdoptionDestination,
    DocumentAdoptionProposal, DocumentContentRead, DocumentRead, DocumentReadRequest,
    DocumentRevision, DocumentRevisionPage, DocumentRevisionRequest, DocumentTarget,
    DriveFileMetadata, DriveId, EvidenceSource, FolderId, GoogleFileId, GoogleUser,
    OAuthScopeReceipt, ProbeStatus, SharedDriveMetadata, WorkspaceProbeRequest,
    WorkspaceProbeResult, canonicalize_document_text, sha256_hex,
};

/// An in-memory access token.  It is intentionally not serializable and its
/// Debug representation never contains the token bytes.
pub struct AccessToken(String);

impl AccessToken {
    pub fn new(value: impl Into<String>) -> Result<Self, GoogleWorkspaceError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(GoogleWorkspaceError::InvalidInput {
                field: "Google OAuth access token",
                reason: String::from("must not be empty"),
            });
        }
        Ok(Self(value))
    }

    pub(crate) fn expose(&self) -> &str {
        &self.0
    }

    pub fn digest(&self) -> String {
        sha256_hex(self.0.as_bytes())
    }
}

impl Clone for AccessToken {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl fmt::Debug for AccessToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccessToken")
            .field("digest", &self.digest())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiEndpoints {
    pub oauth_tokeninfo: Url,
    pub drive_api: Url,
    pub docs_api: Url,
}

impl ApiEndpoints {
    pub fn production() -> Self {
        Self {
            oauth_tokeninfo: Url::parse(crate::GOOGLE_OAUTH_TOKENINFO_URL)
                .expect("Google OAuth tokeninfo URL is static and valid"),
            drive_api: Url::parse(crate::GOOGLE_DRIVE_API_BASE_URL)
                .expect("Google Drive API URL is static and valid"),
            docs_api: Url::parse(crate::GOOGLE_DOCS_API_BASE_URL)
                .expect("Google Docs API URL is static and valid"),
        }
    }

    pub fn loopback(base_url: impl AsRef<str>) -> Result<Self, GoogleWorkspaceError> {
        let base_url =
            Url::parse(base_url.as_ref()).map_err(|error| GoogleWorkspaceError::InvalidInput {
                field: "loopback API base URL",
                reason: error.to_string(),
            })?;
        let base_url = ensure_trailing_slash(base_url);
        Ok(Self {
            oauth_tokeninfo: base_url.join("tokeninfo").map_err(|error| {
                GoogleWorkspaceError::InvalidInput {
                    field: "loopback OAuth URL",
                    reason: error.to_string(),
                }
            })?,
            drive_api: base_url.join("drive/v3/").map_err(|error| {
                GoogleWorkspaceError::InvalidInput {
                    field: "loopback Drive URL",
                    reason: error.to_string(),
                }
            })?,
            docs_api: base_url.join("docs/v1/").map_err(|error| {
                GoogleWorkspaceError::InvalidInput {
                    field: "loopback Docs URL",
                    reason: error.to_string(),
                }
            })?,
        })
    }

    fn validate(&self, evidence_source: &EvidenceSource) -> Result<(), GoogleWorkspaceError> {
        let endpoints = [
            ("OAuth endpoint", &self.oauth_tokeninfo),
            ("Drive endpoint", &self.drive_api),
            ("Docs endpoint", &self.docs_api),
        ];
        for (field, endpoint) in endpoints {
            let is_loopback = endpoint
                .host_str()
                .is_some_and(|host| matches!(host, "127.0.0.1" | "localhost" | "[::1]"));
            match evidence_source {
                EvidenceSource::NativeHttps if endpoint.scheme() != "https" => {
                    return Err(GoogleWorkspaceError::InvalidInput {
                        field,
                        reason: String::from("native endpoints must use HTTPS"),
                    });
                }
                EvidenceSource::Loopback if endpoint.scheme() != "http" || !is_loopback => {
                    return Err(GoogleWorkspaceError::InvalidInput {
                        field,
                        reason: String::from("loopback endpoints must use localhost HTTP"),
                    });
                }
                _ => {}
            }
        }
        Ok(())
    }
}

/// A provider whose public operations are all read-only.  The transport is
/// injected so deterministic local HTTP coverage can use the same provider
/// code as the native HTTPS path.
pub struct GoogleDriveDocsProvider {
    access_token: AccessToken,
    endpoints: ApiEndpoints,
    transport: Arc<dyn HttpTransport>,
    evidence_source: EvidenceSource,
}

impl fmt::Debug for GoogleDriveDocsProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GoogleDriveDocsProvider")
            .field("access_token", &self.access_token)
            .field("endpoints", &self.endpoints)
            .field("evidence_source", &self.evidence_source)
            .finish_non_exhaustive()
    }
}

impl GoogleDriveDocsProvider {
    pub fn production(access_token: AccessToken) -> Result<Self, GoogleWorkspaceError> {
        let transport =
            ReqwestTransport::production().map_err(|error| transport_config_error(&error))?;
        Self::with_transport(
            access_token,
            ApiEndpoints::production(),
            Arc::new(transport),
            EvidenceSource::NativeHttps,
        )
    }

    pub fn from_environment() -> Result<Self, GoogleWorkspaceError> {
        let value = env::var(crate::GOOGLE_WORKSPACE_ACCESS_TOKEN_ENV).map_err(|_| {
            GoogleWorkspaceError::BlockedEnv {
                variable: crate::GOOGLE_WORKSPACE_ACCESS_TOKEN_ENV,
            }
        })?;
        if value.trim().is_empty() {
            return Err(GoogleWorkspaceError::BlockedEnv {
                variable: crate::GOOGLE_WORKSPACE_ACCESS_TOKEN_ENV,
            });
        }
        Self::production(AccessToken::new(value)?)
    }

    pub fn loopback(
        access_token: AccessToken,
        base_url: impl AsRef<str>,
    ) -> Result<Self, GoogleWorkspaceError> {
        let endpoints = ApiEndpoints::loopback(base_url)?;
        let transport =
            ReqwestTransport::loopback().map_err(|error| transport_config_error(&error))?;
        Self::with_transport(
            access_token,
            endpoints,
            Arc::new(transport),
            EvidenceSource::Loopback,
        )
    }

    pub fn with_transport(
        access_token: AccessToken,
        endpoints: ApiEndpoints,
        transport: Arc<dyn HttpTransport>,
        evidence_source: EvidenceSource,
    ) -> Result<Self, GoogleWorkspaceError> {
        endpoints.validate(&evidence_source)?;
        Ok(Self {
            access_token,
            endpoints,
            transport,
            evidence_source,
        })
    }

    pub fn evidence_source(&self) -> &EvidenceSource {
        &self.evidence_source
    }

    pub const fn external_write_available(&self) -> bool {
        false
    }

    pub fn probe_from_environment(request: &WorkspaceProbeRequest) -> ProbeOutcome {
        match Self::from_environment() {
            Ok(provider) => match provider.probe(request) {
                Ok(result) => ProbeOutcome::Completed(Box::new(result)),
                Err(error) => ProbeOutcome::Failed(error),
            },
            Err(GoogleWorkspaceError::BlockedEnv { variable }) => {
                ProbeOutcome::BlockedEnv { variable }
            }
            Err(error) => ProbeOutcome::Failed(error),
        }
    }

    pub fn probe(
        &self,
        request: &WorkspaceProbeRequest,
    ) -> Result<WorkspaceProbeResult, GoogleWorkspaceError> {
        request.scope.validate()?;
        let (oauth, user) = self.probe_oauth()?;
        let initial_change_cursor = self.start_change_cursor(&request.scope)?;
        let shared_drive = match &request.scope.corpus {
            crate::model::ChangeCorpus::User => None,
            crate::model::ChangeCorpus::SharedDrive { drive_id } => {
                Some(self.read_shared_drive(drive_id)?)
            }
        };
        let folder = match &request.scope.folder_id {
            Some(folder_id) => Some(self.read_folder_metadata(folder_id, &request.scope.corpus)?),
            None => None,
        };
        let document = request
            .document_id
            .as_ref()
            .map(|document_id| {
                self.read_document(&DocumentReadRequest {
                    document_id: document_id.clone(),
                    scope: request.scope.clone(),
                })
            })
            .transpose()?;
        let status = match self.evidence_source {
            EvidenceSource::NativeHttps => ProbeStatus::Connected,
            EvidenceSource::Loopback => ProbeStatus::VerifiedLoopbackNotConnected,
            EvidenceSource::Fixture => ProbeStatus::VerifiedFixtureNotConnected,
            EvidenceSource::Injected => ProbeStatus::VerifiedInjectedNotConnected,
        };
        Ok(WorkspaceProbeResult {
            status,
            evidence_source: self.evidence_source.clone(),
            oauth,
            user,
            corpus: request.scope.clone(),
            shared_drive,
            folder,
            document,
            initial_change_cursor,
        })
    }

    pub fn read_document_metadata(
        &self,
        document_id: &crate::model::DocumentId,
    ) -> Result<DriveFileMetadata, GoogleWorkspaceError> {
        let url = self.drive_path(
            &format!("files/{}", document_id.as_str()),
            &[
                ("fields", String::from("id,name,mimeType,parents,driveId,trashed,createdTime,modifiedTime,version,webViewLink")),
                ("supportsAllDrives", String::from("true")),
            ],
        )?;
        let raw = self.get_json::<RawDriveFile>("drive.files.get", &url)?;
        parse_drive_file(raw, Some(document_id.as_str()))
    }

    pub fn read_document_content(
        &self,
        document_id: &crate::model::DocumentId,
    ) -> Result<DocumentContentRead, GoogleWorkspaceError> {
        let url = self.docs_path(&format!("documents/{}", document_id.as_str()), &[])?;
        let raw = self.get_json_value("docs.documents.get", &url)?;
        parse_document_content(&raw, document_id)
    }

    pub fn read_document_revisions(
        &self,
        request: &DocumentRevisionRequest,
    ) -> Result<DocumentRevisionPage, GoogleWorkspaceError> {
        let url = self.drive_path(
            &format!("files/{}/revisions", request.document_id.as_str()),
            &[
                ("fields", String::from("revisions(id,modifiedTime,keepForever,published,size,lastModifyingUser(permissionId,displayName,emailAddress,photoLink)),nextPageToken")),
                ("pageSize", request.page_size.to_string()),
                ("supportsAllDrives", String::from("true")),
            ],
        )?;
        let raw = self.get_json::<RawRevisionPage>("drive.revisions.list", &url)?;
        parse_revision_page(raw, &request.document_id)
    }

    pub fn read_document(
        &self,
        request: &DocumentReadRequest,
    ) -> Result<DocumentRead, GoogleWorkspaceError> {
        request.scope.validate()?;
        let metadata = self.read_document_metadata(&request.document_id)?;
        if !metadata.is_google_doc() {
            return Err(GoogleWorkspaceError::InvalidInput {
                field: "document MIME type",
                reason: format!("{} is not a Google Docs document", metadata.mime_type),
            });
        }
        let location = location_from_metadata(&metadata);
        if !is_within_scope(&metadata, &request.scope) {
            return Err(GoogleWorkspaceError::CorpusMoved {
                resource: request.document_id.to_string(),
            });
        }
        let content = self.read_document_content(&request.document_id)?;
        if content.document_id.as_str() != request.document_id.as_str() {
            return Err(GoogleWorkspaceError::InvalidResponse {
                endpoint: String::from("docs.documents.get"),
                message: String::from("document ID did not match the requested ID"),
            });
        }
        Ok(DocumentRead {
            document_id: request.document_id.clone(),
            title: content.title.clone(),
            metadata,
            provider_revision: content.provider_revision.clone(),
            content: content.content,
            location,
        })
    }

    pub fn start_change_cursor(
        &self,
        scope: &ChangeScope,
    ) -> Result<ChangeCursor, GoogleWorkspaceError> {
        scope.validate()?;
        let mut parameters = vec![("supportsAllDrives", String::from("true"))];
        if let crate::model::ChangeCorpus::SharedDrive { drive_id } = &scope.corpus {
            parameters.push(("driveId", drive_id.to_string()));
        }
        let url = self.drive_path("changes/startPageToken", &parameters)?;
        let raw = self.get_json::<RawStartPageToken>("drive.changes.getStartPageToken", &url)?;
        ChangeCursor::new(scope.corpus.clone(), raw.start_page_token)
    }

    pub fn read_change_page(
        &self,
        request: &ChangePageRequest,
    ) -> Result<ChangePage, GoogleWorkspaceError> {
        request.scope.validate()?;
        let mut parameters = vec![
            ("pageToken", request.cursor.page_token.clone()),
            ("pageSize", request.page_size.to_string()),
            ("spaces", String::from("drive")),
            ("includeItemsFromAllDrives", String::from("true")),
            ("supportsAllDrives", String::from("true")),
        ];
        if let crate::model::ChangeCorpus::SharedDrive { drive_id } = &request.scope.corpus {
            parameters.push(("driveId", drive_id.to_string()));
        }
        let url = self.drive_path("changes", &parameters)?;
        let raw = match self.get_json::<RawChangePage>("drive.changes.list", &url) {
            Ok(raw) => raw,
            Err(GoogleWorkspaceError::Http { status: 410, .. }) => {
                return Err(GoogleWorkspaceError::ChangeCursorExpired {
                    corpus: request.scope.corpus.label(),
                });
            }
            Err(error) => return Err(error),
        };
        let entries = raw
            .changes
            .unwrap_or_default()
            .into_iter()
            .map(parse_change)
            .collect::<Result<Vec<_>, _>>()?;
        let next_cursor = raw
            .next_page_token
            .map(|token| ChangeCursor::new(request.scope.corpus.clone(), token))
            .transpose()?;
        let new_start_cursor = raw
            .new_start_page_token
            .map(|token| ChangeCursor::new(request.scope.corpus.clone(), token))
            .transpose()?;
        Ok(ChangePage {
            scope: request.scope.clone(),
            entries,
            next_cursor,
            new_start_cursor,
        })
    }

    pub fn classify_change(
        &self,
        change: &ChangeRecord,
        scope: &ChangeScope,
    ) -> Result<ChangeClassification, GoogleWorkspaceError> {
        if let Some(file) = &change.file {
            let disposition = if file.trashed {
                ChangeDisposition::Deleted
            } else if change.removed {
                ChangeDisposition::AmbiguousRemoval
            } else if !is_within_scope(file, scope) {
                ChangeDisposition::CorpusMoved
            } else {
                ChangeDisposition::Current
            };
            return Ok(ChangeClassification {
                file_id: change.file_id.clone(),
                disposition,
                reason: String::from(
                    "the Drive change entry carries current item state, not a field delta",
                ),
            });
        }

        match self.read_file_metadata(&change.file_id) {
            Ok(file) if file.trashed => Ok(ChangeClassification {
                file_id: change.file_id.clone(),
                disposition: ChangeDisposition::Deleted,
                reason: String::from("the metadata probe confirmed the item is trashed"),
            }),
            Ok(file) if !is_within_scope(&file, scope) => Ok(ChangeClassification {
                file_id: change.file_id.clone(),
                disposition: ChangeDisposition::CorpusMoved,
                reason: String::from(
                    "the metadata probe found the item outside the observed corpus",
                ),
            }),
            Ok(_) => Ok(ChangeClassification {
                file_id: change.file_id.clone(),
                disposition: ChangeDisposition::AmbiguousRemoval,
                reason: String::from(
                    "the provider still returned the item but the removal reason is not exposed",
                ),
            }),
            Err(GoogleWorkspaceError::AccessDenied { .. }) => Ok(ChangeClassification {
                file_id: change.file_id.clone(),
                disposition: ChangeDisposition::AccessLost,
                reason: String::from("the metadata probe was rejected with access denied"),
            }),
            Err(GoogleWorkspaceError::NotFound { .. }) => Ok(ChangeClassification {
                file_id: change.file_id.clone(),
                disposition: ChangeDisposition::AmbiguousRemoval,
                reason: String::from(
                    "Drive does not distinguish deletion from access loss for this 404",
                ),
            }),
            Err(error) => Err(error),
        }
    }

    pub fn propose_document_adoption(
        &self,
        selection: crate::model::MissionWorkProductSelection,
        destination: DocumentAdoptionDestination,
    ) -> Result<DocumentAdoptionProposal, GoogleWorkspaceError> {
        let selection = selection.validate()?;
        let (target, required_provider_revision, batch_update) = match destination {
            DocumentAdoptionDestination::Create {
                corpus,
                folder_id,
                title,
            } => {
                if title.trim().is_empty() {
                    return Err(GoogleWorkspaceError::InvalidInput {
                        field: "proposed document title",
                        reason: String::from("must not be empty"),
                    });
                }
                let batch_update = DocsBatchUpdatePayload {
                    write_control: None,
                    requests: insert_request(&selection.content),
                };
                (
                    DocumentTarget {
                        operation: AdoptionOperation::CreateDocument,
                        corpus,
                        folder_id,
                        document_id: None,
                        title: Some(title),
                    },
                    None,
                    batch_update,
                )
            }
            DocumentAdoptionDestination::Update {
                document,
                required_provider_revision,
            } => {
                if required_provider_revision.trim().is_empty() {
                    return Err(GoogleWorkspaceError::InvalidInput {
                        field: "required provider revision",
                        reason: String::from("must not be empty"),
                    });
                }
                if required_provider_revision != document.provider_revision {
                    return Err(GoogleWorkspaceError::RevisionConflict {
                        expected: required_provider_revision,
                        actual: document.provider_revision,
                    });
                }
                let batch_update = DocsBatchUpdatePayload {
                    write_control: Some(DocsWriteControl {
                        required_revision_id: document.provider_revision.clone(),
                    }),
                    requests: replace_body_requests(&document.content, &selection.content),
                };
                (
                    DocumentTarget {
                        operation: AdoptionOperation::UpdateDocument,
                        corpus: corpus_from_location(&document.location),
                        folder_id: document.metadata.parents.first().cloned(),
                        document_id: Some(document.document_id),
                        title: Some(document.title.clone()),
                    },
                    Some(required_provider_revision),
                    batch_update,
                )
            }
        };
        DocumentAdoptionProposal {
            schema_version: String::from(crate::GOOGLE_WORKSPACE_SCHEMA_VERSION),
            provider_id: String::from(crate::GOOGLE_WORKSPACE_PROVIDER_ID),
            service_id: String::from(crate::GOOGLE_WORKSPACE_SERVICE_ID),
            target,
            work_product: selection.clone(),
            required_provider_revision,
            canonical_content: selection.content.clone(),
            canonical_content_digest: sha256_hex(selection.content.as_bytes()),
            batch_update,
            mutating: false,
            proposal_digest: String::new(),
        }
        .with_digest()
        .and_then(|proposal| {
            proposal.validate()?;
            Ok(proposal)
        })
    }

    fn probe_oauth(&self) -> Result<(OAuthScopeReceipt, GoogleUser), GoogleWorkspaceError> {
        let mut tokeninfo_url = self.endpoints.oauth_tokeninfo.clone();
        tokeninfo_url
            .query_pairs_mut()
            .append_pair("access_token", self.access_token.expose());
        let tokeninfo = match self.get_json::<RawTokenInfo>("oauth.tokeninfo", &tokeninfo_url) {
            Ok(value) => value,
            Err(GoogleWorkspaceError::Http { status, body, .. }) => {
                return Err(GoogleWorkspaceError::OAuthRejected {
                    status,
                    reason: body,
                });
            }
            Err(GoogleWorkspaceError::AuthenticationRejected { status, .. }) => {
                return Err(GoogleWorkspaceError::OAuthRejected {
                    status,
                    reason: String::from("access token was rejected or revoked"),
                });
            }
            Err(GoogleWorkspaceError::AccessDenied { resource }) => {
                return Err(GoogleWorkspaceError::OAuthRejected {
                    status: 403,
                    reason: resource,
                });
            }
            Err(error) => return Err(error),
        };
        let expires_in_seconds = parse_expires_in(tokeninfo.expires_in)?;
        if expires_in_seconds == 0 {
            return Err(GoogleWorkspaceError::OAuthTokenExpired);
        }
        let granted_scopes = tokeninfo
            .scope
            .unwrap_or_default()
            .split_whitespace()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        let required_scopes = crate::REQUIRED_OAUTH_SCOPES
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        if let Some(scope) = required_scopes.difference(&granted_scopes).next().cloned() {
            return Err(GoogleWorkspaceError::MissingOAuthScope { scope });
        }
        let about_url = self.drive_path("about", &[("fields", String::from("user"))])?;
        let about = self.get_json::<RawAbout>("drive.about.get", &about_url)?;
        let user =
            about
                .user
                .map(parse_user)
                .ok_or_else(|| GoogleWorkspaceError::InvalidResponse {
                    endpoint: String::from("drive.about.get"),
                    message: String::from("response did not contain user"),
                })?;
        Ok((
            OAuthScopeReceipt {
                granted_scopes,
                required_scopes,
                expires_in_seconds,
                audience: tokeninfo.aud,
                token_digest: self.access_token.digest(),
            },
            user,
        ))
    }

    fn read_shared_drive(
        &self,
        drive_id: &DriveId,
    ) -> Result<SharedDriveMetadata, GoogleWorkspaceError> {
        let url = self.drive_path(
            &format!("drives/{drive_id}"),
            &[("fields", String::from("id,name,hidden,restrictions"))],
        )?;
        let raw = self.get_json::<RawSharedDrive>("drive.drives.get", &url)?;
        let id = DriveId::new(
            raw.id
                .ok_or_else(|| missing_response("drive.drives.get", "id"))?,
        )?;
        Ok(SharedDriveMetadata {
            id,
            name: raw.name.unwrap_or_default(),
            hidden: raw.hidden.unwrap_or(false),
            restrictions: raw.restrictions,
        })
    }

    fn read_folder_metadata(
        &self,
        folder_id: &FolderId,
        corpus: &crate::model::ChangeCorpus,
    ) -> Result<DriveFileMetadata, GoogleWorkspaceError> {
        let metadata = self.read_file_metadata(&GoogleFileId::new(folder_id.as_str())?)?;
        if !metadata.is_folder() {
            return Err(GoogleWorkspaceError::InvalidInput {
                field: "folder MIME type",
                reason: format!("{} is not a Google Drive folder", metadata.mime_type),
            });
        }
        if !is_in_corpus(&metadata, corpus) {
            return Err(GoogleWorkspaceError::CorpusMoved {
                resource: folder_id.to_string(),
            });
        }
        Ok(metadata)
    }

    fn read_file_metadata(
        &self,
        file_id: &GoogleFileId,
    ) -> Result<DriveFileMetadata, GoogleWorkspaceError> {
        let url = self.drive_path(
            &format!("files/{}", file_id.as_str()),
            &[
                ("fields", String::from("id,name,mimeType,parents,driveId,trashed,createdTime,modifiedTime,version,webViewLink")),
                ("supportsAllDrives", String::from("true")),
            ],
        )?;
        let raw = self.get_json::<RawDriveFile>("drive.files.get", &url)?;
        parse_drive_file(raw, Some(file_id.as_str()))
    }

    fn drive_path(
        &self,
        path: &str,
        parameters: &[(&str, String)],
    ) -> Result<Url, GoogleWorkspaceError> {
        let mut url = self.endpoints.drive_api.join(path).map_err(|error| {
            GoogleWorkspaceError::InvalidInput {
                field: "Drive API path",
                reason: error.to_string(),
            }
        })?;
        {
            let mut query = url.query_pairs_mut();
            for (name, value) in parameters {
                query.append_pair(name, value);
            }
        }
        Ok(url)
    }

    fn docs_path(
        &self,
        path: &str,
        parameters: &[(&str, String)],
    ) -> Result<Url, GoogleWorkspaceError> {
        let mut url = self.endpoints.docs_api.join(path).map_err(|error| {
            GoogleWorkspaceError::InvalidInput {
                field: "Docs API path",
                reason: error.to_string(),
            }
        })?;
        {
            let mut query = url.query_pairs_mut();
            for (name, value) in parameters {
                query.append_pair(name, value);
            }
        }
        Ok(url)
    }

    fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        endpoint: &str,
        url: &Url,
    ) -> Result<T, GoogleWorkspaceError> {
        let request = HttpRequest::get(url.clone()).with_bearer(self.access_token.expose());
        let response = self.transport.send(&request).map_err(|error| match error {
            TransportError::Request { message } => GoogleWorkspaceError::Transport {
                endpoint: endpoint.to_owned(),
                message,
            },
            TransportError::ResponseTooLarge { limit } => GoogleWorkspaceError::ResponseTooLarge {
                endpoint: endpoint.to_owned(),
                limit,
            },
        })?;
        if !(200..300).contains(&response.status) {
            return Err(map_http_error(endpoint, response.status, &response.body));
        }
        serde_json::from_slice(&response.body).map_err(|error| {
            GoogleWorkspaceError::InvalidResponse {
                endpoint: endpoint.to_owned(),
                message: error.to_string(),
            }
        })
    }

    fn get_json_value(&self, endpoint: &str, url: &Url) -> Result<Value, GoogleWorkspaceError> {
        self.get_json(endpoint, url)
    }
}

/// A result is completed only when the native HTTPS provider has authenticated
/// successfully.  Loopback and injected evidence are deliberately distinct.
#[derive(Debug)]
pub enum ProbeOutcome {
    Completed(Box<WorkspaceProbeResult>),
    BlockedEnv { variable: &'static str },
    Failed(GoogleWorkspaceError),
}

impl ProbeOutcome {
    pub const fn is_connected(&self) -> bool {
        match self {
            Self::Completed(result) => matches!(result.status, ProbeStatus::Connected),
            Self::BlockedEnv { .. } | Self::Failed(_) => false,
        }
    }
}

/// Typed service definition consumed by a Mission result-adoption flow.
pub trait ResultWorkspaceService {
    fn probe(
        &self,
        request: &WorkspaceProbeRequest,
    ) -> Result<WorkspaceProbeResult, GoogleWorkspaceError>;
    fn read_document_metadata(
        &self,
        document_id: &crate::model::DocumentId,
    ) -> Result<DriveFileMetadata, GoogleWorkspaceError>;
    fn read_document_content(
        &self,
        document_id: &crate::model::DocumentId,
    ) -> Result<DocumentContentRead, GoogleWorkspaceError>;
    fn read_document_revisions(
        &self,
        request: &DocumentRevisionRequest,
    ) -> Result<DocumentRevisionPage, GoogleWorkspaceError>;
    fn read_document(
        &self,
        request: &DocumentReadRequest,
    ) -> Result<DocumentRead, GoogleWorkspaceError>;
    fn start_change_cursor(
        &self,
        scope: &ChangeScope,
    ) -> Result<ChangeCursor, GoogleWorkspaceError>;
    fn read_change_page(
        &self,
        request: &ChangePageRequest,
    ) -> Result<ChangePage, GoogleWorkspaceError>;
    fn classify_change(
        &self,
        change: &ChangeRecord,
        scope: &ChangeScope,
    ) -> Result<ChangeClassification, GoogleWorkspaceError>;
    fn propose_document_adoption(
        &self,
        selection: crate::model::MissionWorkProductSelection,
        destination: DocumentAdoptionDestination,
    ) -> Result<DocumentAdoptionProposal, GoogleWorkspaceError>;
}

impl ResultWorkspaceService for GoogleDriveDocsProvider {
    fn probe(
        &self,
        request: &WorkspaceProbeRequest,
    ) -> Result<WorkspaceProbeResult, GoogleWorkspaceError> {
        Self::probe(self, request)
    }

    fn read_document_metadata(
        &self,
        document_id: &crate::model::DocumentId,
    ) -> Result<DriveFileMetadata, GoogleWorkspaceError> {
        Self::read_document_metadata(self, document_id)
    }

    fn read_document_content(
        &self,
        document_id: &crate::model::DocumentId,
    ) -> Result<DocumentContentRead, GoogleWorkspaceError> {
        Self::read_document_content(self, document_id)
    }

    fn read_document_revisions(
        &self,
        request: &DocumentRevisionRequest,
    ) -> Result<DocumentRevisionPage, GoogleWorkspaceError> {
        Self::read_document_revisions(self, request)
    }

    fn read_document(
        &self,
        request: &DocumentReadRequest,
    ) -> Result<DocumentRead, GoogleWorkspaceError> {
        Self::read_document(self, request)
    }

    fn start_change_cursor(
        &self,
        scope: &ChangeScope,
    ) -> Result<ChangeCursor, GoogleWorkspaceError> {
        Self::start_change_cursor(self, scope)
    }

    fn read_change_page(
        &self,
        request: &ChangePageRequest,
    ) -> Result<ChangePage, GoogleWorkspaceError> {
        Self::read_change_page(self, request)
    }

    fn classify_change(
        &self,
        change: &ChangeRecord,
        scope: &ChangeScope,
    ) -> Result<ChangeClassification, GoogleWorkspaceError> {
        Self::classify_change(self, change, scope)
    }

    fn propose_document_adoption(
        &self,
        selection: crate::model::MissionWorkProductSelection,
        destination: DocumentAdoptionDestination,
    ) -> Result<DocumentAdoptionProposal, GoogleWorkspaceError> {
        Self::propose_document_adoption(self, selection, destination)
    }
}

#[derive(Debug, Deserialize)]
struct RawTokenInfo {
    scope: Option<String>,
    aud: Option<String>,
    expires_in: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct RawAbout {
    user: Option<RawUser>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawUser {
    permission_id: Option<String>,
    display_name: Option<String>,
    email_address: Option<String>,
    photo_link: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawSharedDrive {
    id: Option<String>,
    name: Option<String>,
    hidden: Option<bool>,
    restrictions: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawDriveFile {
    id: Option<String>,
    name: Option<String>,
    mime_type: Option<String>,
    parents: Option<Vec<String>>,
    drive_id: Option<String>,
    trashed: Option<bool>,
    created_time: Option<String>,
    modified_time: Option<String>,
    version: Option<String>,
    web_view_link: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawRevisionPage {
    revisions: Option<Vec<RawRevision>>,
    next_page_token: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawRevision {
    id: Option<String>,
    modified_time: Option<String>,
    keep_forever: Option<bool>,
    published: Option<bool>,
    size: Option<Value>,
    last_modifying_user: Option<RawUser>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawStartPageToken {
    start_page_token: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawChangePage {
    changes: Option<Vec<RawChange>>,
    next_page_token: Option<String>,
    new_start_page_token: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawChange {
    id: Option<String>,
    file_id: Option<String>,
    removed: Option<bool>,
    file: Option<RawDriveFile>,
    time: Option<String>,
    change_type: Option<String>,
}

fn ensure_trailing_slash(mut url: Url) -> Url {
    if !url.path().ends_with('/') {
        let path = format!("{}/", url.path());
        url.set_path(&path);
    }
    url
}

fn transport_config_error(error: &TransportError) -> GoogleWorkspaceError {
    GoogleWorkspaceError::Transport {
        endpoint: String::from("transport configuration"),
        message: error.to_string(),
    }
}

fn missing_response(endpoint: &str, field: &str) -> GoogleWorkspaceError {
    GoogleWorkspaceError::InvalidResponse {
        endpoint: endpoint.to_owned(),
        message: format!("response did not contain {field}"),
    }
}

fn map_http_error(endpoint: &str, status: u16, body: &[u8]) -> GoogleWorkspaceError {
    let body = summarize_body(body);
    match status {
        401 => GoogleWorkspaceError::AuthenticationRejected {
            endpoint: endpoint.to_owned(),
            status,
        },
        403 => GoogleWorkspaceError::AccessDenied {
            resource: endpoint.to_owned(),
        },
        404 => GoogleWorkspaceError::NotFound {
            resource: endpoint.to_owned(),
        },
        _ => GoogleWorkspaceError::Http {
            endpoint: endpoint.to_owned(),
            status,
            body,
        },
    }
}

fn summarize_body(body: &[u8]) -> String {
    const MAX_ERROR_BODY_BYTES: usize = 512;
    let mut summary = String::from_utf8_lossy(body).replace('\n', " ");
    if summary.len() > MAX_ERROR_BODY_BYTES {
        summary.truncate(MAX_ERROR_BODY_BYTES);
        summary.push('…');
    }
    summary
}

fn parse_expires_in(value: Option<Value>) -> Result<u64, GoogleWorkspaceError> {
    let value = value.ok_or_else(|| missing_response("oauth.tokeninfo", "expires_in"))?;
    match value {
        Value::Number(number) => {
            number
                .as_u64()
                .ok_or_else(|| GoogleWorkspaceError::InvalidResponse {
                    endpoint: String::from("oauth.tokeninfo"),
                    message: String::from("expires_in was not an unsigned integer"),
                })
        }
        Value::String(value) => {
            value
                .parse::<u64>()
                .map_err(|error| GoogleWorkspaceError::InvalidResponse {
                    endpoint: String::from("oauth.tokeninfo"),
                    message: error.to_string(),
                })
        }
        _ => Err(GoogleWorkspaceError::InvalidResponse {
            endpoint: String::from("oauth.tokeninfo"),
            message: String::from("expires_in was not a number or string"),
        }),
    }
}

fn parse_user(raw: RawUser) -> GoogleUser {
    GoogleUser {
        permission_id: raw.permission_id,
        display_name: raw.display_name,
        email_address: raw.email_address,
        photo_link: raw.photo_link,
    }
}

fn parse_drive_file(
    raw: RawDriveFile,
    fallback_id: Option<&str>,
) -> Result<DriveFileMetadata, GoogleWorkspaceError> {
    let id = raw
        .id
        .as_deref()
        .or(fallback_id)
        .ok_or_else(|| missing_response("drive.files.get", "id"))
        .and_then(GoogleFileId::new)?;
    let parents = raw
        .parents
        .unwrap_or_default()
        .into_iter()
        .map(FolderId::new)
        .collect::<Result<Vec<_>, _>>()?;
    let drive_id = raw.drive_id.map(DriveId::new).transpose()?;
    Ok(DriveFileMetadata {
        id,
        name: raw.name.unwrap_or_default(),
        mime_type: raw.mime_type.unwrap_or_default(),
        parents,
        drive_id,
        trashed: raw.trashed.unwrap_or(false),
        created_time: raw.created_time,
        modified_time: raw.modified_time,
        version: raw.version,
        web_view_link: raw.web_view_link,
    })
}

fn parse_document_content(
    raw: &Value,
    expected_id: &crate::model::DocumentId,
) -> Result<DocumentContentRead, GoogleWorkspaceError> {
    let document_id = raw
        .get("documentId")
        .and_then(Value::as_str)
        .ok_or_else(|| missing_response("docs.documents.get", "documentId"))
        .and_then(crate::model::DocumentId::new)?;
    let title = raw
        .get("title")
        .and_then(Value::as_str)
        .ok_or_else(|| missing_response("docs.documents.get", "title"))?
        .to_owned();
    let provider_revision = raw
        .get("revisionId")
        .and_then(Value::as_str)
        .ok_or_else(|| missing_response("docs.documents.get", "revisionId"))?
        .to_owned();
    let content = raw
        .get("body")
        .and_then(|body| body.get("content"))
        .ok_or_else(|| missing_response("docs.documents.get", "body.content"))?;
    let mut text = String::new();
    let mut body_end_index = 1;
    extract_text_and_end_index(content, &mut text, &mut body_end_index);
    let text = canonicalize_document_text(&text);
    if document_id != *expected_id {
        return Err(GoogleWorkspaceError::InvalidResponse {
            endpoint: String::from("docs.documents.get"),
            message: String::from("document ID did not match the requested ID"),
        });
    }
    Ok(DocumentContentRead {
        document_id,
        title,
        provider_revision,
        content: CanonicalDocumentContent {
            digest: sha256_hex(text.as_bytes()),
            text,
            body_end_index,
        },
    })
}

fn extract_text_and_end_index(value: &Value, text: &mut String, body_end_index: &mut u64) {
    match value {
        Value::Array(values) => values
            .iter()
            .for_each(|value| extract_text_and_end_index(value, text, body_end_index)),
        Value::Object(object) => {
            if let Some(end_index) = object.get("endIndex").and_then(Value::as_u64) {
                *body_end_index = (*body_end_index).max(end_index);
            }
            if let Some(content) = object
                .get("textRun")
                .and_then(|text_run| text_run.get("content"))
                .and_then(Value::as_str)
            {
                text.push_str(content);
            } else {
                object
                    .values()
                    .for_each(|value| extract_text_and_end_index(value, text, body_end_index));
            }
        }
        _ => {}
    }
}

fn parse_revision_page(
    raw: RawRevisionPage,
    document_id: &crate::model::DocumentId,
) -> Result<DocumentRevisionPage, GoogleWorkspaceError> {
    let revisions = raw
        .revisions
        .unwrap_or_default()
        .into_iter()
        .map(|revision| {
            Ok(DocumentRevision {
                id: revision
                    .id
                    .ok_or_else(|| missing_response("drive.revisions.list", "revision id"))?,
                modified_time: revision.modified_time,
                keep_forever: revision.keep_forever.unwrap_or(false),
                published: revision.published.unwrap_or(false),
                size: revision.size.map(parse_optional_u64).transpose()?,
                last_modifying_user: revision.last_modifying_user.map(parse_user),
            })
        })
        .collect::<Result<Vec<_>, GoogleWorkspaceError>>()?;
    Ok(DocumentRevisionPage {
        document_id: document_id.clone(),
        revisions,
        next_page_token: raw.next_page_token,
    })
}

fn parse_optional_u64(value: Value) -> Result<u64, GoogleWorkspaceError> {
    match value {
        Value::Number(number) => {
            number
                .as_u64()
                .ok_or_else(|| GoogleWorkspaceError::InvalidResponse {
                    endpoint: String::from("drive.revisions.list"),
                    message: String::from("revision size was not an unsigned integer"),
                })
        }
        Value::String(value) => {
            value
                .parse::<u64>()
                .map_err(|error| GoogleWorkspaceError::InvalidResponse {
                    endpoint: String::from("drive.revisions.list"),
                    message: error.to_string(),
                })
        }
        _ => Err(GoogleWorkspaceError::InvalidResponse {
            endpoint: String::from("drive.revisions.list"),
            message: String::from("revision size was not a number or string"),
        }),
    }
}

fn parse_change(raw: RawChange) -> Result<ChangeRecord, GoogleWorkspaceError> {
    let file_id = raw
        .file_id
        .ok_or_else(|| missing_response("drive.changes.list", "fileId"))
        .and_then(GoogleFileId::new)?;
    let file = raw
        .file
        .map(|raw_file| parse_drive_file(raw_file, Some(file_id.as_str())))
        .transpose()?;
    let change_type = match raw.change_type.as_deref() {
        Some("file") => ChangeType::File,
        Some("drive") => ChangeType::Drive,
        _ => ChangeType::Unknown,
    };
    Ok(ChangeRecord {
        change_id: raw.id,
        file_id,
        removed: raw.removed.unwrap_or(false),
        file,
        time: raw.time,
        change_type,
    })
}

fn location_from_metadata(metadata: &DriveFileMetadata) -> CorpusLocation {
    match &metadata.drive_id {
        Some(drive_id) => CorpusLocation::SharedDrive {
            drive_id: drive_id.clone(),
        },
        None => CorpusLocation::User { drive_id: None },
    }
}

fn corpus_from_location(location: &CorpusLocation) -> crate::model::ChangeCorpus {
    match location {
        CorpusLocation::User { .. } => crate::model::ChangeCorpus::User,
        CorpusLocation::SharedDrive { drive_id } => crate::model::ChangeCorpus::SharedDrive {
            drive_id: drive_id.clone(),
        },
    }
}

fn is_in_corpus(metadata: &DriveFileMetadata, corpus: &crate::model::ChangeCorpus) -> bool {
    match corpus {
        crate::model::ChangeCorpus::User => true,
        crate::model::ChangeCorpus::SharedDrive { drive_id } => {
            metadata.drive_id.as_ref() == Some(drive_id)
        }
    }
}

fn is_within_scope(metadata: &DriveFileMetadata, scope: &ChangeScope) -> bool {
    is_in_corpus(metadata, &scope.corpus)
        && scope
            .folder_id
            .as_ref()
            .is_none_or(|folder_id| metadata.parents.iter().any(|parent| parent == folder_id))
}

fn insert_request(content: &str) -> Vec<DocsBatchRequest> {
    if content.is_empty() {
        Vec::new()
    } else {
        vec![DocsBatchRequest::InsertText {
            insert_text: DocsInsertText {
                location: DocsLocation { index: 1 },
                text: content.to_owned(),
            },
        }]
    }
}

fn replace_body_requests(
    existing: &CanonicalDocumentContent,
    content: &str,
) -> Vec<DocsBatchRequest> {
    let mut requests = Vec::new();
    let end_index = existing.body_end_index.saturating_sub(1);
    if end_index > 1 {
        requests.push(DocsBatchRequest::DeleteContentRange {
            delete_content_range: DocsDeleteContentRange {
                range: DocsRange {
                    start_index: 1,
                    end_index,
                },
            },
        });
    }
    requests.extend(insert_request(content));
    requests
}
