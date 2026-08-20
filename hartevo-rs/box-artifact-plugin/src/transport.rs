use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Deserialize;
use url::Url;
use zeroize::Zeroizing;

use crate::error::{BoxArtifactError, BoxTransportError};
use crate::model::{
    BoxArtifactScope, BoxContentResponse, BoxFileRecord, BoxFolderItemsPage, BoxFolderRecord,
    BoxUserRecord, BoxVersionPage, BoxVersionRecord, ByteRange, FileId, FolderId,
    ProviderProvenance, SecretReference, UserId, VersionId,
};

/// Credential material is resolved for one provider call and is never part of
/// a registration, projection, request log, or error string.
#[derive(Clone)]
pub struct SecretMaterial(Zeroizing<String>);

impl SecretMaterial {
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for SecretMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretMaterial(<redacted>)")
    }
}

/// The provider transport surface is intentionally GET-only.  There is no
/// upload, overwrite, move, delete, share, or collaboration method in Layer 1.
pub trait BoxArtifactTransport: fmt::Debug + Send + Sync {
    fn provenance(&self) -> ProviderProvenance;

    fn get_user(
        &self,
        token: &SecretMaterial,
        enterprise_id: &crate::EnterpriseId,
        user_id: &crate::UserId,
    ) -> Result<BoxUserRecord, BoxTransportError>;

    fn get_folder(
        &self,
        token: &SecretMaterial,
        scope: &BoxArtifactScope,
        folder_id: &FolderId,
    ) -> Result<BoxFolderRecord, BoxTransportError>;

    fn list_folder_items(
        &self,
        token: &SecretMaterial,
        scope: &BoxArtifactScope,
        folder_id: &FolderId,
        offset: u64,
        limit: u32,
    ) -> Result<BoxFolderItemsPage, BoxTransportError>;

    fn get_file(
        &self,
        token: &SecretMaterial,
        scope: &BoxArtifactScope,
        file_id: &FileId,
    ) -> Result<BoxFileRecord, BoxTransportError>;

    fn list_file_versions(
        &self,
        token: &SecretMaterial,
        scope: &BoxArtifactScope,
        file_id: &FileId,
        offset: u64,
        limit: u32,
    ) -> Result<BoxVersionPage, BoxTransportError>;

    fn get_content(
        &self,
        token: &SecretMaterial,
        scope: &BoxArtifactScope,
        file_id: &FileId,
        version_id: &VersionId,
        range: ByteRange,
    ) -> Result<BoxContentResponse, BoxTransportError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BoxTransportOperation {
    GetUser,
    GetFolder,
    ListFolderItems,
    GetFile,
    ListFileVersions,
    GetContent,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FixtureFileFailure {
    AccessLost,
    NotFound,
    Unknown,
}

#[derive(Clone)]
pub struct BoxArtifactFixture {
    pub user: BoxUserRecord,
    pub folders: BTreeMap<FolderId, BoxFolderRecord>,
    pub folder_items: BTreeMap<FolderId, Vec<BoxFileRecord>>,
    pub files: BTreeMap<FileId, BoxFileRecord>,
    pub versions: BTreeMap<FileId, Vec<BoxVersionRecord>>,
    pub content: BTreeMap<(FileId, VersionId), Vec<u8>>,
    file_failures: BTreeMap<FileId, FixtureFileFailure>,
    folder_failures: BTreeMap<FolderId, FixtureFileFailure>,
    content_ranges: BTreeMap<(FileId, VersionId), ByteRange>,
}

impl fmt::Debug for BoxArtifactFixture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoxArtifactFixture")
            .field("user", &self.user)
            .field("folder_count", &self.folders.len())
            .field("folder_item_count", &self.folder_items.len())
            .field("file_count", &self.files.len())
            .field("version_count", &self.versions.len())
            .field("content_count", &self.content.len())
            .finish_non_exhaustive()
    }
}

impl BoxArtifactFixture {
    pub fn new(user: BoxUserRecord) -> Self {
        Self {
            user,
            folders: BTreeMap::new(),
            folder_items: BTreeMap::new(),
            files: BTreeMap::new(),
            versions: BTreeMap::new(),
            content: BTreeMap::new(),
            file_failures: BTreeMap::new(),
            folder_failures: BTreeMap::new(),
            content_ranges: BTreeMap::new(),
        }
    }

    pub fn insert_folder(&mut self, folder: BoxFolderRecord) {
        self.folders.insert(folder.folder_id.clone(), folder);
    }

    pub fn insert_file(&mut self, file: BoxFileRecord, bytes: Vec<u8>) {
        let key = (file.file_id.clone(), file.version_id.clone());
        self.content.insert(key, bytes);
        self.folder_items
            .entry(file.parent_folder_id.clone())
            .or_default()
            .push(file.clone());
        self.files.insert(file.file_id.clone(), file);
    }

    pub fn insert_versions(&mut self, file_id: FileId, versions: Vec<BoxVersionRecord>) {
        self.versions.insert(file_id, versions);
    }

    pub fn set_file_failure(&mut self, file_id: FileId, failure: FixtureFileFailure) {
        self.file_failures.insert(file_id, failure);
    }

    pub fn set_folder_failure(&mut self, folder_id: FolderId, failure: FixtureFileFailure) {
        self.folder_failures.insert(folder_id, failure);
    }

    pub fn set_content_range(&mut self, file_id: FileId, version_id: VersionId, range: ByteRange) {
        self.content_ranges.insert((file_id, version_id), range);
    }
}

#[derive(Clone)]
pub struct FixtureBoxArtifactTransport {
    fixture: Arc<Mutex<BoxArtifactFixture>>,
    provenance: ProviderProvenance,
    operations: Arc<Mutex<Vec<BoxTransportOperation>>>,
}

impl fmt::Debug for FixtureBoxArtifactTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FixtureBoxArtifactTransport")
            .field("provenance", &self.provenance)
            .finish_non_exhaustive()
    }
}

impl FixtureBoxArtifactTransport {
    pub fn fixture(fixture: BoxArtifactFixture) -> Self {
        Self::new(fixture, ProviderProvenance::Fixture)
    }

    pub fn loopback(fixture: BoxArtifactFixture) -> Self {
        Self::new(fixture, ProviderProvenance::Loopback)
    }

    pub fn new(fixture: BoxArtifactFixture, provenance: ProviderProvenance) -> Self {
        assert!(matches!(
            provenance,
            ProviderProvenance::Fixture | ProviderProvenance::Loopback
        ));
        Self {
            fixture: Arc::new(Mutex::new(fixture)),
            provenance,
            operations: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn operations(&self) -> Vec<BoxTransportOperation> {
        self.operations
            .lock()
            .map_or_else(|_| Vec::new(), |operations| operations.clone())
    }

    pub fn update_fixture(&self, update: impl FnOnce(&mut BoxArtifactFixture)) {
        if let Ok(mut fixture) = self.fixture.lock() {
            update(&mut fixture);
        }
    }

    fn record(&self, operation: BoxTransportOperation) -> Result<(), BoxTransportError> {
        self.operations
            .lock()
            .map_err(|_| BoxTransportError::Network)?
            .push(operation);
        Ok(())
    }

    fn fixture_guard(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, BoxArtifactFixture>, BoxTransportError> {
        self.fixture.lock().map_err(|_| BoxTransportError::Network)
    }

    fn validate_token(token: &SecretMaterial) -> Result<(), BoxTransportError> {
        if token.as_str().trim().is_empty() || token.as_str().chars().any(char::is_control) {
            Err(BoxTransportError::Unauthorized)
        } else {
            Ok(())
        }
    }

    fn failure(failure: Option<&FixtureFileFailure>) -> Result<(), BoxTransportError> {
        match failure {
            Some(FixtureFileFailure::AccessLost) => Err(BoxTransportError::Forbidden),
            Some(FixtureFileFailure::NotFound) => Err(BoxTransportError::NotFound),
            Some(FixtureFileFailure::Unknown) => {
                Err(BoxTransportError::UnexpectedStatus { status: 500 })
            }
            None => Ok(()),
        }
    }
}

impl BoxArtifactTransport for FixtureBoxArtifactTransport {
    fn provenance(&self) -> ProviderProvenance {
        self.provenance.clone()
    }

    fn get_user(
        &self,
        token: &SecretMaterial,
        enterprise_id: &crate::EnterpriseId,
        user_id: &crate::UserId,
    ) -> Result<BoxUserRecord, BoxTransportError> {
        self.record(BoxTransportOperation::GetUser)?;
        Self::validate_token(token)?;
        let fixture = self.fixture_guard()?;
        if &fixture.user.enterprise_id != enterprise_id || &fixture.user.user_id != user_id {
            return Err(BoxTransportError::Forbidden);
        }
        Ok(fixture.user.clone())
    }

    fn get_folder(
        &self,
        token: &SecretMaterial,
        scope: &BoxArtifactScope,
        folder_id: &FolderId,
    ) -> Result<BoxFolderRecord, BoxTransportError> {
        self.record(BoxTransportOperation::GetFolder)?;
        Self::validate_token(token)?;
        let fixture = self.fixture_guard()?;
        Self::failure(fixture.folder_failures.get(folder_id))?;
        let folder = fixture
            .folders
            .get(folder_id)
            .ok_or(BoxTransportError::NotFound)?;
        if folder.enterprise_id != scope.enterprise_id || folder.user_id != scope.user_id {
            return Err(BoxTransportError::Forbidden);
        }
        Ok(folder.clone())
    }

    fn list_folder_items(
        &self,
        token: &SecretMaterial,
        scope: &BoxArtifactScope,
        folder_id: &FolderId,
        offset: u64,
        limit: u32,
    ) -> Result<BoxFolderItemsPage, BoxTransportError> {
        self.record(BoxTransportOperation::ListFolderItems)?;
        Self::validate_token(token)?;
        let fixture = self.fixture_guard()?;
        Self::failure(fixture.folder_failures.get(folder_id))?;
        let items = fixture
            .folder_items
            .get(folder_id)
            .ok_or(BoxTransportError::NotFound)?;
        let Some(folder) = fixture.folders.get(folder_id) else {
            return Err(BoxTransportError::NotFound);
        };
        if folder.enterprise_id != scope.enterprise_id || folder.user_id != scope.user_id {
            return Err(BoxTransportError::Forbidden);
        }
        let start = usize::try_from(offset).map_err(|_| BoxTransportError::RangeMismatch)?;
        let end = start.saturating_add(limit as usize).min(items.len());
        let entries = items.get(start..end).unwrap_or_default().to_vec();
        let next_offset = (end < items.len()).then_some(end as u64);
        Ok(BoxFolderItemsPage {
            folder_id: folder_id.clone(),
            offset,
            total_count: items.len() as u64,
            entries,
            next_offset,
        })
    }

    fn get_file(
        &self,
        token: &SecretMaterial,
        scope: &BoxArtifactScope,
        file_id: &FileId,
    ) -> Result<BoxFileRecord, BoxTransportError> {
        self.record(BoxTransportOperation::GetFile)?;
        Self::validate_token(token)?;
        let fixture = self.fixture_guard()?;
        Self::failure(fixture.file_failures.get(file_id))?;
        let file = fixture
            .files
            .get(file_id)
            .ok_or(BoxTransportError::NotFound)?;
        if file.enterprise_id != scope.enterprise_id || file.owner_user_id != scope.user_id {
            return Err(BoxTransportError::Forbidden);
        }
        Ok(file.clone())
    }

    fn list_file_versions(
        &self,
        token: &SecretMaterial,
        scope: &BoxArtifactScope,
        file_id: &FileId,
        offset: u64,
        limit: u32,
    ) -> Result<BoxVersionPage, BoxTransportError> {
        self.record(BoxTransportOperation::ListFileVersions)?;
        Self::validate_token(token)?;
        let fixture = self.fixture_guard()?;
        Self::failure(fixture.file_failures.get(file_id))?;
        let file = fixture
            .files
            .get(file_id)
            .ok_or(BoxTransportError::NotFound)?;
        if file.enterprise_id != scope.enterprise_id || file.owner_user_id != scope.user_id {
            return Err(BoxTransportError::Forbidden);
        }
        let entries = fixture.versions.get(file_id).cloned().unwrap_or_default();
        let start = usize::try_from(offset).map_err(|_| BoxTransportError::RangeMismatch)?;
        let end = start.saturating_add(limit as usize).min(entries.len());
        let page_entries = entries.get(start..end).unwrap_or_default().to_vec();
        Ok(BoxVersionPage {
            file_id: file_id.clone(),
            offset,
            total_count: entries.len() as u64,
            entries: page_entries,
            next_offset: (end < entries.len()).then_some(end as u64),
        })
    }

    fn get_content(
        &self,
        token: &SecretMaterial,
        scope: &BoxArtifactScope,
        file_id: &FileId,
        version_id: &VersionId,
        range: ByteRange,
    ) -> Result<BoxContentResponse, BoxTransportError> {
        self.record(BoxTransportOperation::GetContent)?;
        Self::validate_token(token)?;
        let fixture = self.fixture_guard()?;
        Self::failure(fixture.file_failures.get(file_id))?;
        let Some(file) = fixture.files.get(file_id) else {
            return Err(BoxTransportError::NotFound);
        };
        if file.enterprise_id != scope.enterprise_id || file.owner_user_id != scope.user_id {
            return Err(BoxTransportError::Forbidden);
        }
        let Some(bytes) = fixture.content.get(&(file_id.clone(), version_id.clone())) else {
            return Err(BoxTransportError::NotFound);
        };
        let start = usize::try_from(range.start).map_err(|_| BoxTransportError::RangeMismatch)?;
        let requested_end =
            usize::try_from(range.end_inclusive).map_err(|_| BoxTransportError::RangeMismatch)?;
        let bytes = if start < bytes.len() {
            bytes[start..=requested_end.min(bytes.len().saturating_sub(1))].to_vec()
        } else {
            Vec::new()
        };
        let returned_range = fixture
            .content_ranges
            .get(&(file_id.clone(), version_id.clone()))
            .copied()
            .unwrap_or(range);
        Ok(BoxContentResponse {
            file_id: file_id.clone(),
            version_id: version_id.clone(),
            range: returned_range,
            status: 206,
            bytes,
        })
    }
}

/// Production HTTPS transport.  It supports only authenticated GETs and is
/// deliberately not enabled by the environment resolver unless the host opts
/// into that boundary explicitly.
pub struct UreqBoxArtifactTransport {
    base_url: String,
    agent: ureq::Agent,
}

impl fmt::Debug for UreqBoxArtifactTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UreqBoxArtifactTransport")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl UreqBoxArtifactTransport {
    pub fn production() -> Result<Self, BoxArtifactError> {
        Self::new(crate::BOX_API_BASE_URL)
    }

    pub fn new(base_url: impl Into<String>) -> Result<Self, BoxArtifactError> {
        let base_url = base_url.into().trim_end_matches('/').to_owned();
        let parsed = Url::parse(&base_url).map_err(|_| BoxArtifactError::InvalidConfiguration)?;
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(BoxArtifactError::InvalidConfiguration);
        }
        let agent = ureq::Agent::config_builder()
            .user_agent("hartevo-box-artifact/1")
            .timeout_global(Some(Duration::from_secs(20)))
            .build()
            .into();
        Ok(Self { base_url, agent })
    }

    fn endpoint(
        &self,
        segments: &[&str],
        query: &[(&str, String)],
    ) -> Result<String, BoxTransportError> {
        let mut url =
            Url::parse(&self.base_url).map_err(|_| BoxTransportError::InvalidConfiguration)?;
        {
            let mut path = url
                .path_segments_mut()
                .map_err(|()| BoxTransportError::InvalidConfiguration)?;
            for segment in segments {
                path.push(segment);
            }
        }
        if !query.is_empty() {
            let mut pairs = url.query_pairs_mut();
            for (key, value) in query {
                pairs.append_pair(key, value);
            }
        }
        Ok(url.to_string())
    }

    fn get_json<T: for<'de> Deserialize<'de>>(
        &self,
        token: &SecretMaterial,
        segments: &[&str],
        query: &[(&str, String)],
    ) -> Result<T, BoxTransportError> {
        let url = self.endpoint(segments, query)?;
        let mut response = self
            .agent
            .get(&url)
            .header("Authorization", format!("Bearer {}", token.as_str()))
            .header("Accept", "application/json")
            .call()
            .map_err(|error| classify_ureq_error(&error))?;
        let body = response
            .body_mut()
            .with_config()
            .limit(crate::MAX_RESPONSE_BYTES as u64)
            .read_to_vec()
            .map_err(|_| BoxTransportError::Network)?;
        if body.len() > crate::MAX_RESPONSE_BYTES {
            return Err(BoxTransportError::ResponseTooLarge);
        }
        serde_json::from_slice(&body).map_err(|_| BoxTransportError::Decode)
    }

    fn get_content_response(
        &self,
        token: &SecretMaterial,
        segments: &[&str],
        query: &[(&str, String)],
        file_id: &FileId,
        version_id: &VersionId,
        range: ByteRange,
    ) -> Result<BoxContentResponse, BoxTransportError> {
        let url = self.endpoint(segments, query)?;
        let mut response = self
            .agent
            .get(&url)
            .header("Authorization", format!("Bearer {}", token.as_str()))
            .header("Accept", "application/octet-stream")
            .header("Range", range.header_value())
            .call()
            .map_err(|error| classify_ureq_error(&error))?;
        let status = response.status().as_u16();
        let body = response
            .body_mut()
            .with_config()
            .limit(crate::MAX_RESPONSE_BYTES as u64)
            .read_to_vec()
            .map_err(|_| BoxTransportError::Network)?;
        let max_content_bytes = usize::try_from(crate::MAX_CONTENT_BYTES)
            .map_err(|_| BoxTransportError::ResponseTooLarge)?;
        if body.len() > max_content_bytes {
            return Err(BoxTransportError::ResponseTooLarge);
        }
        let returned_range = response
            .headers()
            .get("content-range")
            .and_then(|value| value.to_str().ok())
            .and_then(parse_content_range)
            .unwrap_or(range);
        Ok(BoxContentResponse {
            file_id: file_id.clone(),
            version_id: version_id.clone(),
            range: returned_range,
            status,
            bytes: body,
        })
    }
}

impl BoxArtifactTransport for UreqBoxArtifactTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::NativeHttps
    }

    fn get_user(
        &self,
        token: &SecretMaterial,
        enterprise_id: &crate::EnterpriseId,
        user_id: &crate::UserId,
    ) -> Result<BoxUserRecord, BoxTransportError> {
        let raw: RawUser = self.get_json(token, &["users", user_id.as_str()], &[])?;
        parse_user(raw, enterprise_id, user_id)
    }

    fn get_folder(
        &self,
        token: &SecretMaterial,
        scope: &BoxArtifactScope,
        folder_id: &FolderId,
    ) -> Result<BoxFolderRecord, BoxTransportError> {
        let raw: RawFolder = self.get_json(token, &["folders", folder_id.as_str()], &[])?;
        parse_folder(raw, scope, folder_id)
    }

    fn list_folder_items(
        &self,
        token: &SecretMaterial,
        scope: &BoxArtifactScope,
        folder_id: &FolderId,
        offset: u64,
        limit: u32,
    ) -> Result<BoxFolderItemsPage, BoxTransportError> {
        let raw: RawFolderItems = self.get_json(
            token,
            &["folders", folder_id.as_str(), "items"],
            &[
                ("offset", offset.to_string()),
                ("limit", limit.to_string()),
                (
                    "fields",
                    String::from(
                        "id,name,content_type,size,sha1,version_id,file_version,parent,owned_by,trashed_at",
                    ),
                ),
            ],
        )?;
        let entries = raw
            .entries
            .into_iter()
            .map(|entry| parse_file(entry, scope))
            .collect::<Result<Vec<_>, _>>()?;
        let next_offset = (offset.saturating_add(entries.len() as u64) < raw.total_count)
            .then_some(offset.saturating_add(entries.len() as u64));
        Ok(BoxFolderItemsPage {
            folder_id: folder_id.clone(),
            offset,
            total_count: raw.total_count,
            entries,
            next_offset,
        })
    }

    fn get_file(
        &self,
        token: &SecretMaterial,
        scope: &BoxArtifactScope,
        file_id: &FileId,
    ) -> Result<BoxFileRecord, BoxTransportError> {
        let raw: RawFile = self.get_json(token, &["files", file_id.as_str()], &[])?;
        parse_file(raw, scope)
    }

    fn list_file_versions(
        &self,
        token: &SecretMaterial,
        scope: &BoxArtifactScope,
        file_id: &FileId,
        offset: u64,
        limit: u32,
    ) -> Result<BoxVersionPage, BoxTransportError> {
        let raw: RawVersionPage = self.get_json(
            token,
            &["files", file_id.as_str(), "versions"],
            &[("offset", offset.to_string()), ("limit", limit.to_string())],
        )?;
        let entries = raw
            .entries
            .into_iter()
            .map(|entry| parse_version(entry, file_id))
            .collect::<Result<Vec<_>, _>>()?;
        let _ = scope;
        let next_offset = (offset.saturating_add(entries.len() as u64) < raw.total_count)
            .then_some(offset.saturating_add(entries.len() as u64));
        Ok(BoxVersionPage {
            file_id: file_id.clone(),
            offset,
            total_count: raw.total_count,
            entries,
            next_offset,
        })
    }

    fn get_content(
        &self,
        token: &SecretMaterial,
        scope: &BoxArtifactScope,
        file_id: &FileId,
        version_id: &VersionId,
        range: ByteRange,
    ) -> Result<BoxContentResponse, BoxTransportError> {
        let response = self.get_content_response(
            token,
            &["files", file_id.as_str(), "content"],
            &[("version", version_id.as_str().to_owned())],
            file_id,
            version_id,
            range,
        )?;
        let _ = scope;
        Ok(response)
    }
}

#[derive(Deserialize)]
struct RawUser {
    id: String,
    name: Option<String>,
    login: Option<String>,
    #[serde(default)]
    enterprise: Option<RawIdentity>,
}

#[derive(Deserialize)]
struct RawFolder {
    id: String,
    name: String,
    #[serde(default)]
    parent: Option<RawIdentity>,
    #[serde(default)]
    owned_by: Option<RawIdentity>,
}

#[derive(Deserialize)]
struct RawFolderItems {
    #[serde(default)]
    entries: Vec<RawFile>,
    #[serde(default)]
    total_count: u64,
}

#[derive(Deserialize)]
struct RawFile {
    id: String,
    name: String,
    #[serde(default)]
    content_type: Option<String>,
    #[serde(default)]
    size: u64,
    sha1: String,
    #[serde(default)]
    version_id: Option<String>,
    #[serde(default)]
    file_version: Option<RawFileVersion>,
    #[serde(default)]
    parent: Option<RawIdentity>,
    #[serde(default)]
    owned_by: Option<RawIdentity>,
    #[serde(default)]
    trashed_at: Option<String>,
}

#[derive(Deserialize)]
struct RawVersionPage {
    #[serde(default)]
    entries: Vec<RawVersion>,
    #[serde(default)]
    total_count: u64,
}

#[derive(Deserialize)]
struct RawVersion {
    id: String,
    #[serde(default)]
    size: u64,
    sha1: String,
    #[serde(default)]
    trashed_at: Option<String>,
}

#[derive(Deserialize)]
struct RawFileVersion {
    id: String,
}

#[derive(Deserialize)]
struct RawIdentity {
    id: String,
}

fn parse_user(
    raw: RawUser,
    enterprise_id: &crate::EnterpriseId,
    user_id: &crate::UserId,
) -> Result<BoxUserRecord, BoxTransportError> {
    let actual_user = crate::UserId::new(raw.id).map_err(|_| BoxTransportError::Decode)?;
    if actual_user != *user_id {
        return Err(BoxTransportError::Forbidden);
    }
    let actual_enterprise = raw
        .enterprise
        .map(|identity| crate::EnterpriseId::new(identity.id))
        .transpose()
        .map_err(|_| BoxTransportError::Decode)?
        .unwrap_or_else(|| enterprise_id.clone());
    if actual_enterprise != *enterprise_id {
        return Err(BoxTransportError::Forbidden);
    }
    Ok(BoxUserRecord {
        enterprise_id: actual_enterprise,
        user_id: actual_user,
        display_name: raw.name,
        email_address: raw.login,
    })
}

fn parse_folder(
    raw: RawFolder,
    scope: &BoxArtifactScope,
    folder_id: &FolderId,
) -> Result<BoxFolderRecord, BoxTransportError> {
    let actual_folder = FolderId::new(raw.id).map_err(|_| BoxTransportError::Decode)?;
    if actual_folder != *folder_id {
        return Err(BoxTransportError::Forbidden);
    }
    let parent_folder_id = raw
        .parent
        .map(|identity| FolderId::new(identity.id))
        .transpose()
        .map_err(|_| BoxTransportError::Decode)?;
    let _ = raw.owned_by;
    Ok(BoxFolderRecord {
        enterprise_id: scope.enterprise_id.clone(),
        user_id: scope.user_id.clone(),
        folder_id: actual_folder,
        parent_folder_id,
        name: raw.name,
    })
}

fn parse_file(raw: RawFile, scope: &BoxArtifactScope) -> Result<BoxFileRecord, BoxTransportError> {
    let file_id = FileId::new(raw.id).map_err(|_| BoxTransportError::Decode)?;
    let parent_folder_id = raw
        .parent
        .ok_or(BoxTransportError::Decode)
        .and_then(|identity| FolderId::new(identity.id).map_err(|_| BoxTransportError::Decode))?;
    let owner_user_id = raw
        .owned_by
        .ok_or(BoxTransportError::Decode)
        .and_then(|identity| UserId::new(identity.id).map_err(|_| BoxTransportError::Decode))?;
    if owner_user_id != scope.user_id {
        return Err(BoxTransportError::Forbidden);
    }
    let sha1 = crate::Sha1Digest::new(raw.sha1).map_err(|_| BoxTransportError::Decode)?;
    let version_value = raw
        .version_id
        .or_else(|| raw.file_version.map(|version| version.id))
        .ok_or(BoxTransportError::Decode)?;
    let version_id = VersionId::new(version_value).map_err(|_| BoxTransportError::Decode)?;
    Ok(BoxFileRecord {
        enterprise_id: scope.enterprise_id.clone(),
        owner_user_id,
        file_id,
        parent_folder_id,
        name: raw.name,
        media_type: raw
            .content_type
            .unwrap_or_else(|| String::from("application/octet-stream")),
        size: raw.size,
        sha1,
        version_id,
        trashed: raw.trashed_at.is_some(),
        deleted: false,
    })
}

fn parse_version(raw: RawVersion, file_id: &FileId) -> Result<BoxVersionRecord, BoxTransportError> {
    Ok(BoxVersionRecord {
        file_id: file_id.clone(),
        version_id: VersionId::new(raw.id).map_err(|_| BoxTransportError::Decode)?,
        size: raw.size,
        sha1: crate::Sha1Digest::new(raw.sha1).map_err(|_| BoxTransportError::Decode)?,
        trashed: raw.trashed_at.is_some(),
        deleted: false,
    })
}

fn parse_content_range(value: &str) -> Option<ByteRange> {
    let (unit, range) = value.split_once(' ')?;
    if unit != "bytes" {
        return None;
    }
    let (start, end) = range.split_once('-')?;
    ByteRange::new(start.parse().ok()?, end.parse().ok()?).ok()
}

fn classify_ureq_error(error: &ureq::Error) -> BoxTransportError {
    match error {
        ureq::Error::StatusCode(401) => BoxTransportError::Unauthorized,
        ureq::Error::StatusCode(403) => BoxTransportError::Forbidden,
        ureq::Error::StatusCode(404) => BoxTransportError::NotFound,
        ureq::Error::StatusCode(410) => BoxTransportError::Gone,
        ureq::Error::StatusCode(429) => BoxTransportError::RateLimited {
            retry_after_seconds: None,
        },
        ureq::Error::StatusCode(status) if *status >= 500 => {
            BoxTransportError::UnexpectedStatus { status: *status }
        }
        ureq::Error::StatusCode(status) => BoxTransportError::UnexpectedStatus { status: *status },
        _ => BoxTransportError::Network,
    }
}

impl SecretReference {
    pub fn resolve_key(&self) -> (&str, u64) {
        (&self.reference_id, self.credential_revision)
    }
}
