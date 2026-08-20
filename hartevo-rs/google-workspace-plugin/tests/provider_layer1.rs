use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use hartevo_google_workspace_plugin::{
    AccessToken, AdoptionOperation, CanonicalDocumentContent, ChangeCorpus, ChangeDisposition,
    ChangeRecord, ChangeScope, ChangeType, CorpusLocation, DocumentAdoptionDestination, DocumentId,
    DocumentRead, DriveFileMetadata, EvidenceSource, FolderId, GoogleDriveDocsProvider,
    GoogleFileId, GoogleWorkspaceError, MissionAdoptionRequest, MissionResultWorkspaceConsumer,
    MissionWorkProductSelection, PluginScope, ProbeStatus, ReadOnlyAuthority,
    WorkspaceProbeRequest,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use url::Url;

type Handler = dyn Fn(&Url, &BTreeMap<String, String>) -> (u16, String) + Send + Sync + 'static;

#[derive(Clone, Debug)]
struct RequestRecord {
    method: String,
    path: String,
    query: BTreeMap<String, String>,
    has_authorization: bool,
}

struct TestServer {
    base_url: String,
    stop: Arc<AtomicBool>,
    requests: Arc<Mutex<Vec<RequestRecord>>>,
    handle: Option<JoinHandle<()>>,
}

impl TestServer {
    fn new<F>(max_requests: usize, handler: F) -> Self
    where
        F: Fn(&Url, &BTreeMap<String, String>) -> (u16, String) + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback server");
        listener
            .set_nonblocking(true)
            .expect("make loopback server nonblocking");
        let address = listener.local_addr().expect("loopback server address");
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let thread_stop = Arc::clone(&stop);
        let thread_requests = Arc::clone(&requests);
        let handler: Arc<Handler> = Arc::new(handler);
        let thread_handler = Arc::clone(&handler);
        let handle = thread::spawn(move || {
            let mut served = 0;
            while !thread_stop.load(Ordering::Relaxed) && served < max_requests {
                match listener.accept() {
                    Ok((stream, _)) => {
                        serve_request(stream, thread_handler.as_ref(), &thread_requests);
                        served += 1;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            base_url: format!("http://{address}"),
            stop,
            requests,
            handle: Some(handle),
        }
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn requests(&self) -> Vec<RequestRecord> {
        self.requests.lock().expect("request records lock").clone()
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            handle.join().expect("loopback server thread");
        }
    }
}

fn serve_request(mut stream: TcpStream, handler: &Handler, records: &Mutex<Vec<RequestRecord>>) {
    stream
        .set_nonblocking(false)
        .expect("make accepted stream blocking");
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let read = stream.read(&mut buffer).expect("read HTTP request");
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..read]);
        if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    let request = String::from_utf8(bytes).expect("HTTP request UTF-8");
    let mut lines = request.split("\r\n");
    let request_line = lines.next().expect("HTTP request line");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().expect("HTTP method").to_owned();
    let target = parts.next().expect("HTTP target");
    let mut headers = BTreeMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
        }
    }
    let url = Url::parse(&format!("http://loopback{target}")).expect("parse test request URL");
    let query = url
        .query_pairs()
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect::<BTreeMap<_, _>>();
    records
        .lock()
        .expect("request records lock")
        .push(RequestRecord {
            method,
            path: url.path().to_owned(),
            query: query.clone(),
            has_authorization: headers.contains_key("authorization"),
        });
    let (status, body) = handler(&url, &query);
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        410 => "Gone",
        _ => "Test Response",
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .expect("write HTTP response");
}

#[allow(clippy::too_many_lines)]
fn standard_router(url: &Url, query: &BTreeMap<String, String>) -> (u16, String) {
    match url.path() {
        "/tokeninfo" => (
            200,
            json!({
                "scope": "https://www.googleapis.com/auth/drive.metadata.readonly https://www.googleapis.com/auth/documents.readonly",
                "expires_in": 3600,
                "aud": "test-client"
            })
            .to_string(),
        ),
        "/drive/v3/about" => (
            200,
            json!({
                "user": {
                    "permissionId": "perm-1",
                    "displayName": "Test User",
                    "emailAddress": "test@example.com"
                }
            })
            .to_string(),
        ),
        "/drive/v3/changes/startPageToken" => {
            let token = if query.get("driveId").map(String::as_str) == Some("drive-1") {
                "shared-start"
            } else {
                "user-start"
            };
            (200, json!({ "startPageToken": token }).to_string())
        }
        "/drive/v3/changes" if query.get("pageToken") == Some(&String::from("expired")) => {
            (410, json!({ "error": { "message": "expired" } }).to_string())
        }
        "/drive/v3/changes" => (
            200,
            json!({
                "changes": [{
                    "id": "change-1",
                    "fileId": "doc-user",
                    "removed": false,
                    "changeType": "file",
                    "file": {
                        "id": "doc-user",
                        "name": "User Doc",
                        "mimeType": "application/vnd.google-apps.document",
                        "parents": ["folder-user"],
                        "trashed": false
                    }
                }],
                "nextPageToken": "next-page",
                "newStartPageToken": "new-start"
            })
            .to_string(),
        ),
        "/drive/v3/drives/drive-1" => (
            200,
            json!({ "id": "drive-1", "name": "Shared Drive", "hidden": false }).to_string(),
        ),
        "/drive/v3/files/folder-user" => (
            200,
            json!({
                "id": "folder-user",
                "name": "User Folder",
                "mimeType": "application/vnd.google-apps.folder",
                "parents": [],
                "trashed": false
            })
            .to_string(),
        ),
        "/drive/v3/files/folder-shared" => (
            200,
            json!({
                "id": "folder-shared",
                "name": "Shared Folder",
                "mimeType": "application/vnd.google-apps.folder",
                "parents": [],
                "driveId": "drive-1",
                "trashed": false
            })
            .to_string(),
        ),
        "/drive/v3/files/doc-user" => (
            200,
            json!({
                "id": "doc-user",
                "name": "User Doc",
                "mimeType": "application/vnd.google-apps.document",
                "parents": ["folder-user"],
                "trashed": false,
                "version": "7"
            })
            .to_string(),
        ),
        "/drive/v3/files/doc-shared" => (
            200,
            json!({
                "id": "doc-shared",
                "name": "Shared Doc",
                "mimeType": "application/vnd.google-apps.document",
                "parents": ["folder-shared"],
                "driveId": "drive-1",
                "trashed": false,
                "version": "9"
            })
            .to_string(),
        ),
        "/docs/v1/documents/doc-user" => (
            200,
            json!({
                "documentId": "doc-user",
                "title": "User Doc",
                "revisionId": "rev-user",
                "body": { "content": [{ "endIndex": 13, "paragraph": { "elements": [{ "textRun": { "content": "Hello user\n" } }] } }] }
            })
            .to_string(),
        ),
        "/docs/v1/documents/doc-shared" => (
            200,
            json!({
                "documentId": "doc-shared",
                "title": "Shared Doc",
                "revisionId": "rev-shared",
                "body": { "content": [{ "endIndex": 15, "paragraph": { "elements": [{ "textRun": { "content": "Hello shared\n" } }] } }] }
            })
            .to_string(),
        ),
        path if path.ends_with("/revisions") => (
            200,
            json!({
                "revisions": [{ "id": "rev-user", "modifiedTime": "2026-08-14T00:00:00Z", "keepForever": true, "published": false, "size": "12", "lastModifyingUser": { "displayName": "Test User" } }],
                "nextPageToken": "revisions-next"
            })
            .to_string(),
        ),
        _ => (404, json!({ "error": { "message": "route not found" } }).to_string()),
    }
}

fn provider(server: &TestServer) -> GoogleDriveDocsProvider {
    GoogleDriveDocsProvider::loopback(
        AccessToken::new("access-token").expect("test access token"),
        server.base_url(),
    )
    .expect("loopback provider")
}

fn digest(value: &str) -> String {
    let mut output = String::with_capacity(64);
    for byte in Sha256::digest(value.as_bytes()) {
        write!(output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

#[test]
fn loopback_probe_reads_user_and_shared_drive_targets_without_connected_claim() {
    let server = TestServer::new(32, standard_router);
    let provider = provider(&server);
    let user_request = WorkspaceProbeRequest::user(
        Some(FolderId::new("folder-user").expect("folder ID")),
        Some(DocumentId::new("doc-user").expect("document ID")),
    )
    .expect("user probe request");
    let user_result = provider.probe(&user_request).expect("user probe");
    assert_eq!(
        user_result.status,
        ProbeStatus::VerifiedLoopbackNotConnected
    );
    assert_eq!(user_result.evidence_source, EvidenceSource::Loopback);
    assert_eq!(user_result.oauth.expires_in_seconds, 3600);
    assert_eq!(user_result.oauth.granted_scopes.len(), 2);
    assert_eq!(user_result.initial_change_cursor.page_token, "user-start");
    assert_eq!(
        user_result
            .document
            .as_ref()
            .expect("document probe")
            .provider_revision,
        "rev-user"
    );

    let shared_request = WorkspaceProbeRequest::shared_drive(
        hartevo_google_workspace_plugin::DriveId::new("drive-1").expect("drive ID"),
        Some(FolderId::new("folder-shared").expect("folder ID")),
        Some(DocumentId::new("doc-shared").expect("document ID")),
    )
    .expect("shared-drive probe request");
    let shared_result = provider.probe(&shared_request).expect("shared-drive probe");
    assert_eq!(
        shared_result.initial_change_cursor.page_token,
        "shared-start",
        "requests: {:?}",
        server.requests()
    );
    assert_eq!(
        shared_result
            .shared_drive
            .as_ref()
            .expect("shared drive probe")
            .id
            .as_str(),
        "drive-1"
    );
    assert!(!ReadOnlyAuthority::external_write());
    assert!(!provider.external_write_available());
    let requests = server.requests();
    assert!(
        requests
            .iter()
            .all(|request| request.method == "GET" && request.has_authorization)
    );
    assert!(requests.iter().any(|request| {
        request.path == "/drive/v3/changes/startPageToken"
            && request.query.get("driveId").map(String::as_str) == Some("drive-1")
    }));
}

#[test]
fn oauth_expiry_and_revocation_are_not_connected() {
    let expired = TestServer::new(2, |_url, _headers| {
        (
            200,
            json!({
                "scope": "https://www.googleapis.com/auth/drive.metadata.readonly https://www.googleapis.com/auth/documents.readonly",
                "expires_in": 0
            })
            .to_string(),
        )
    });
    let expired_provider = provider(&expired);
    let request = WorkspaceProbeRequest::user(None, None).expect("probe request");
    assert_eq!(
        expired_provider.probe(&request),
        Err(GoogleWorkspaceError::OAuthTokenExpired)
    );

    let revoked = TestServer::new(2, |_url, _headers| {
        (
            401,
            json!({ "error": { "message": "invalid_token" } }).to_string(),
        )
    });
    let revoked_provider = provider(&revoked);
    assert_eq!(
        revoked_provider.probe(&request),
        Err(GoogleWorkspaceError::OAuthRejected {
            status: 401,
            reason: String::from("access token was rejected or revoked"),
        })
    );
}

#[test]
fn change_cursor_pages_are_corpus_bound_and_expired_tokens_require_restart() {
    let server = TestServer::new(16, standard_router);
    let provider = provider(&server);
    let user_scope = ChangeScope::user(None);
    let user_cursor = provider
        .start_change_cursor(&user_scope)
        .expect("user cursor");
    let user_page = provider
        .read_change_page(
            &hartevo_google_workspace_plugin::ChangePageRequest::new(
                user_scope.clone(),
                user_cursor,
                100,
            )
            .expect("user page request"),
        )
        .expect("user page");
    assert_eq!(user_page.entries.len(), 1);
    assert_eq!(
        user_page.next_cursor.expect("next user cursor").page_token,
        "next-page"
    );
    assert_eq!(
        user_page
            .new_start_cursor
            .expect("new user cursor")
            .page_token,
        "new-start"
    );

    let shared_scope = ChangeScope::shared_drive(
        hartevo_google_workspace_plugin::DriveId::new("drive-1").expect("drive ID"),
        None,
    );
    let shared_cursor = provider
        .start_change_cursor(&shared_scope)
        .expect("shared cursor");
    assert_eq!(
        shared_cursor.page_token,
        "shared-start",
        "requests: {:?}",
        server.requests()
    );
    let expired_cursor =
        hartevo_google_workspace_plugin::ChangeCursor::new(ChangeCorpus::User, "expired")
            .expect("expired cursor");
    let error = provider
        .read_change_page(
            &hartevo_google_workspace_plugin::ChangePageRequest::new(
                user_scope.clone(),
                expired_cursor,
                100,
            )
            .expect("expired page request"),
        )
        .expect_err("expired cursor must fail closed");
    assert_eq!(
        error,
        GoogleWorkspaceError::ChangeCursorExpired {
            corpus: String::from("user")
        }
    );
    assert_eq!(
        provider
            .start_change_cursor(&user_scope)
            .expect("restart cursor")
            .page_token,
        "user-start"
    );
}

#[test]
fn deletion_access_loss_corpus_move_and_ambiguous_removal_are_distinct() {
    let server = TestServer::new(8, |url, _headers| match url.path() {
        "/drive/v3/files/lost" => (403, json!({ "error": "forbidden" }).to_string()),
        "/drive/v3/files/gone" => (404, json!({ "error": "notFound" }).to_string()),
        _ => standard_router(url, &BTreeMap::new()),
    });
    let provider = provider(&server);
    let scope = ChangeScope::shared_drive(
        hartevo_google_workspace_plugin::DriveId::new("drive-1").expect("drive ID"),
        None,
    );
    let deleted = ChangeRecord {
        change_id: Some(String::from("deleted")),
        file_id: GoogleFileId::new("deleted").expect("file ID"),
        removed: false,
        file: Some(DriveFileMetadata {
            id: GoogleFileId::new("deleted").expect("file ID"),
            name: String::from("Deleted"),
            mime_type: String::from("application/vnd.google-apps.document"),
            parents: Vec::new(),
            drive_id: Some(
                hartevo_google_workspace_plugin::DriveId::new("drive-1").expect("drive ID"),
            ),
            trashed: true,
            created_time: None,
            modified_time: None,
            version: None,
            web_view_link: None,
        }),
        time: None,
        change_type: ChangeType::File,
    };
    assert_eq!(
        provider
            .classify_change(&deleted, &scope)
            .expect("deleted classification")
            .disposition,
        ChangeDisposition::Deleted
    );
    let access_lost = ChangeRecord {
        change_id: None,
        file_id: GoogleFileId::new("lost").expect("file ID"),
        removed: true,
        file: None,
        time: None,
        change_type: ChangeType::File,
    };
    assert_eq!(
        provider
            .classify_change(&access_lost, &scope)
            .expect("access loss classification")
            .disposition,
        ChangeDisposition::AccessLost
    );
    let corpus_moved = ChangeRecord {
        change_id: None,
        file_id: GoogleFileId::new("moved").expect("file ID"),
        removed: false,
        file: Some(DriveFileMetadata {
            id: GoogleFileId::new("moved").expect("file ID"),
            name: String::from("Moved"),
            mime_type: String::from("application/vnd.google-apps.document"),
            parents: Vec::new(),
            drive_id: Some(
                hartevo_google_workspace_plugin::DriveId::new("drive-2").expect("drive ID"),
            ),
            trashed: false,
            created_time: None,
            modified_time: None,
            version: None,
            web_view_link: None,
        }),
        time: None,
        change_type: ChangeType::File,
    };
    assert_eq!(
        provider
            .classify_change(&corpus_moved, &scope)
            .expect("corpus move classification")
            .disposition,
        ChangeDisposition::CorpusMoved
    );
    let ambiguous = ChangeRecord {
        change_id: None,
        file_id: GoogleFileId::new("gone").expect("file ID"),
        removed: true,
        file: None,
        time: None,
        change_type: ChangeType::File,
    };
    assert_eq!(
        provider
            .classify_change(&ambiguous, &scope)
            .expect("ambiguous classification")
            .disposition,
        ChangeDisposition::AmbiguousRemoval
    );
}

#[test]
fn proposal_is_canonical_revision_fenced_and_non_mutating() {
    let server = TestServer::new(1, standard_router);
    let provider = provider(&server);
    let content = "Adopt me\n";
    let selection = MissionWorkProductSelection::new(
        "tenant-1",
        "project-1",
        "mission-1",
        "work-product-1",
        4,
        2,
        digest(content),
        "Adoptable result",
        content,
    )
    .expect("Work Product selection");
    let create = provider
        .propose_document_adoption(
            selection.clone(),
            DocumentAdoptionDestination::Create {
                corpus: ChangeCorpus::User,
                folder_id: Some(FolderId::new("folder-user").expect("folder ID")),
                title: String::from("Adoptable result"),
            },
        )
        .expect("create proposal");
    assert!(create.is_non_mutating());
    assert_eq!(create.target.operation, AdoptionOperation::CreateDocument);
    assert_eq!(create.target.title.as_deref(), Some("Adoptable result"));
    assert_eq!(create.work_product.work_product_revision, 2);
    assert!(create.required_provider_revision.is_none());
    assert_eq!(create.batch_update.requests.len(), 1);
    assert!(server.requests().is_empty(), "proposal must not call HTTP");

    let document = DocumentRead {
        document_id: DocumentId::new("doc-user").expect("document ID"),
        title: String::from("User Doc"),
        metadata: DriveFileMetadata {
            id: GoogleFileId::new("doc-user").expect("file ID"),
            name: String::from("User Doc"),
            mime_type: String::from("application/vnd.google-apps.document"),
            parents: vec![FolderId::new("folder-user").expect("folder ID")],
            drive_id: None,
            trashed: false,
            created_time: None,
            modified_time: None,
            version: Some(String::from("7")),
            web_view_link: None,
        },
        provider_revision: String::from("rev-user"),
        content: CanonicalDocumentContent {
            text: String::from("Old content\n"),
            digest: digest("Old content\n"),
            body_end_index: 14,
        },
        location: CorpusLocation::User { drive_id: None },
    };
    let update = provider
        .propose_document_adoption(
            selection.clone(),
            DocumentAdoptionDestination::Update {
                document: Box::new(document.clone()),
                required_provider_revision: String::from("rev-user"),
            },
        )
        .expect("update proposal");
    assert!(update.is_non_mutating());
    assert_eq!(update.target.operation, AdoptionOperation::UpdateDocument);
    assert_eq!(
        update
            .batch_update
            .write_control
            .expect("Docs write control")
            .required_revision_id,
        "rev-user"
    );
    assert_eq!(update.canonical_content_digest, digest(content));
    assert_eq!(
        provider.propose_document_adoption(
            selection.clone(),
            DocumentAdoptionDestination::Update {
                document: Box::new(document),
                required_provider_revision: String::from("rev-stale"),
            },
        ),
        Err(GoogleWorkspaceError::RevisionConflict {
            expected: String::from("rev-stale"),
            actual: String::from("rev-user"),
        })
    );
}

#[test]
fn mission_consumer_is_scope_bound_and_revocable() {
    let server = TestServer::new(1, standard_router);
    let provider = provider(&server);
    let scope = PluginScope::new(
        "tenant-1",
        "project-1",
        "account-1",
        ChangeCorpus::User,
        None,
    )
    .expect("plugin scope");
    let registration =
        hartevo_google_workspace_plugin::GoogleWorkspacePluginRegistration::new(scope.clone());
    let consumer = MissionResultWorkspaceConsumer::new(registration.clone());
    let content = "Mission content";
    let selection = MissionWorkProductSelection::new(
        "tenant-1",
        "project-1",
        "mission-1",
        "work-product-1",
        1,
        1,
        digest(content),
        "Mission result",
        content,
    )
    .expect("selection");
    let proposal = consumer
        .propose_adoption(
            &provider,
            MissionAdoptionRequest {
                scope: scope.clone(),
                selection,
                destination: DocumentAdoptionDestination::Create {
                    corpus: ChangeCorpus::User,
                    folder_id: None,
                    title: String::from("Mission result"),
                },
            },
        )
        .expect("Mission proposal");
    assert!(proposal.is_non_mutating());
    let mut revoked = registration;
    revoked.revoke().expect("revoke registration");
    let revoked_consumer = MissionResultWorkspaceConsumer::new(revoked);
    let error = revoked_consumer
        .propose_adoption(
            &provider,
            MissionAdoptionRequest {
                scope,
                selection: MissionWorkProductSelection::new(
                    "tenant-1",
                    "project-1",
                    "mission-1",
                    "work-product-1",
                    1,
                    1,
                    digest(content),
                    "Mission result",
                    content,
                )
                .expect("selection"),
                destination: DocumentAdoptionDestination::Create {
                    corpus: ChangeCorpus::User,
                    folder_id: None,
                    title: String::from("Mission result"),
                },
            },
        )
        .expect_err("revoked registration must fail closed");
    assert_eq!(error, GoogleWorkspaceError::PluginRevoked);
}

#[test]
fn missing_environment_is_blocked_when_no_token_is_configured() {
    if std::env::var(hartevo_google_workspace_plugin::GOOGLE_WORKSPACE_ACCESS_TOKEN_ENV).is_err() {
        let request = WorkspaceProbeRequest::user(None, None).expect("probe request");
        assert!(matches!(
            GoogleDriveDocsProvider::probe_from_environment(&request),
            hartevo_google_workspace_plugin::ProbeOutcome::BlockedEnv { .. }
        ));
    }
}
