use std::{
    collections::VecDeque,
    fmt,
    sync::{Arc, Mutex},
};

use serde::Serialize;

use crate::{
    error::SharePointTransportError,
    model::{
        DeltaChange, Digest, DriveId, DriveItemId, DriveItemKind, GRAPH_API_VERSION, ItemVersionId,
        ListId, MAX_RESPONSE_BYTES, NationalCloud, OpaqueGraphNextLink, ProviderProvenance,
        SHAREPOINT_PROVIDER_REVISION, SharePointKnowledgeScope, SharePointSearchRequest, SiteId,
        canonical_digest, digest_parts, sha256_digest,
    },
};

/// Graph operation names are limited to the five read-only v1.0 seams.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SharePointGraphOperation {
    DriveItemMetadata,
    DriveItemChildren,
    DriveItemSearch,
    DriveItemVersions,
    DriveItemDelta,
}

pub type MicrosoftGraphOperation = SharePointGraphOperation;

/// A request contains only bounded identifiers and digests. Search text and
/// the raw Graph @odata.nextLink never enter a recorded request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MicrosoftGraphRequest {
    pub operation: SharePointGraphOperation,
    pub api_version: String,
    pub national_cloud: NationalCloud,
    pub site_id: SiteId,
    pub drive_id: DriveId,
    pub list_id: ListId,
    pub item_id: DriveItemId,
    pub scope_digest: Digest,
    pub page: u16,
    pub page_size: u16,
    pub cursor_digest: Option<Digest>,
    pub search_digest: Option<Digest>,
}

impl MicrosoftGraphRequest {
    pub fn new(
        operation: SharePointGraphOperation,
        scope: &SharePointKnowledgeScope,
        page: u16,
        cursor: Option<&OpaqueGraphNextLink>,
        search_digest: Option<Digest>,
    ) -> Self {
        Self {
            operation,
            api_version: GRAPH_API_VERSION.to_owned(),
            national_cloud: scope.national_cloud,
            site_id: scope.site_id.clone(),
            drive_id: scope.drive_id.clone(),
            list_id: scope.list_id.clone(),
            item_id: scope.item_id.clone(),
            scope_digest: scope.digest(),
            page,
            page_size: crate::model::PAGE_SIZE,
            cursor_digest: cursor.map(|value| value.digest().to_owned()),
            search_digest,
        }
    }

    /// Returns a safe path/query representation with no raw query or cursor.
    pub fn path_and_query(&self) -> String {
        let base = format!(
            "/{}/sites/{}/drives/{}/items/{}",
            self.api_version, self.site_id, self.drive_id, self.item_id
        );
        match self.operation {
            SharePointGraphOperation::DriveItemMetadata => format!(
                "{base}?$select=id,parentReference,file,folder,size,eTag,cTag,listItem&page={}",
                self.page
            ),
            SharePointGraphOperation::DriveItemChildren => {
                format!("{base}/children?$top={}&page={}", self.page_size, self.page)
            }
            SharePointGraphOperation::DriveItemSearch => format!(
                "/{}/sites/{}/drives/{}/root/search(q='[redacted]')?$top={}&page={}&queryDigest={}",
                self.api_version,
                self.site_id,
                self.drive_id,
                self.page_size,
                self.page,
                self.search_digest.as_deref().unwrap_or("none")
            ),
            SharePointGraphOperation::DriveItemVersions => {
                format!("{base}/versions?$top={}&page={}", self.page_size, self.page)
            }
            SharePointGraphOperation::DriveItemDelta => {
                format!("{base}/delta?$top={}&page={}", self.page_size, self.page)
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SharePointRequestReceipt {
    pub operation: SharePointGraphOperation,
    pub api_version: String,
    pub scope_digest: Digest,
    pub page: u16,
    pub cursor_digest: Option<Digest>,
    pub search_digest: Option<Digest>,
    pub path_digest: Digest,
}

impl SharePointRequestReceipt {
    fn from_request(request: &MicrosoftGraphRequest) -> Self {
        let path_and_query = request.path_and_query();
        Self {
            operation: request.operation,
            api_version: request.api_version.clone(),
            scope_digest: request.scope_digest.clone(),
            page: request.page,
            cursor_digest: request.cursor_digest.clone(),
            search_digest: request.search_digest.clone(),
            path_digest: sha256_digest(path_and_query.as_bytes()),
        }
    }
}

/// Fixture payloads are transport-only. They may contain source names or
/// paths for redaction tests, but no bytes/download URL field exists.
#[derive(Clone)]
pub struct DriveItemMetadataPayload {
    pub site_id: SiteId,
    pub drive_id: DriveId,
    pub list_id: ListId,
    pub item_id: DriveItemId,
    pub parent_item_id: Option<DriveItemId>,
    pub name: String,
    pub kind: DriveItemKind,
    pub size_bytes: Option<u64>,
    pub e_tag: String,
    pub version: ItemVersionId,
    pub permission_digest: Digest,
    pub has_download_url: bool,
}

impl fmt::Debug for DriveItemMetadataPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DriveItemMetadataPayload")
            .field("site_id", &self.site_id)
            .field("drive_id", &self.drive_id)
            .field("list_id", &self.list_id)
            .field("item_id", &self.item_id)
            .field("parent_item_id", &self.parent_item_id)
            .field("name_digest", &sha256_digest(self.name.as_bytes()))
            .field("kind", &self.kind)
            .field("size_bytes", &self.size_bytes)
            .field("e_tag_digest", &sha256_digest(self.e_tag.as_bytes()))
            .field("version", &self.version)
            .field("permission_digest", &self.permission_digest)
            .field("has_download_url", &self.has_download_url)
            .finish()
    }
}

impl DriveItemMetadataPayload {
    pub fn for_scope(
        scope: &SharePointKnowledgeScope,
        name: impl Into<String>,
    ) -> Result<Self, crate::error::SharePointKnowledgeResultError> {
        Ok(Self {
            site_id: scope.site_id.clone(),
            drive_id: scope.drive_id.clone(),
            list_id: scope.list_id.clone(),
            item_id: scope.item_id.clone(),
            parent_item_id: None,
            name: name.into(),
            kind: DriveItemKind::File,
            size_bytes: Some(128),
            e_tag: String::from("fixture-etag"),
            version: scope.item_version.clone(),
            permission_digest: scope.permission_digest.clone(),
            has_download_url: false,
        })
    }
}

#[derive(Clone)]
pub struct DriveItemSearchPayload {
    pub site_id: SiteId,
    pub drive_id: DriveId,
    pub list_id: ListId,
    pub item_id: DriveItemId,
    pub name: String,
    pub path: String,
    pub version: ItemVersionId,
    pub rank: u32,
    pub permission_digest: Digest,
}

impl fmt::Debug for DriveItemSearchPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DriveItemSearchPayload")
            .field("site_id", &self.site_id)
            .field("drive_id", &self.drive_id)
            .field("list_id", &self.list_id)
            .field("item_id", &self.item_id)
            .field("name_digest", &sha256_digest(self.name.as_bytes()))
            .field("path_digest", &sha256_digest(self.path.as_bytes()))
            .field("version", &self.version)
            .field("rank", &self.rank)
            .field("permission_digest", &self.permission_digest)
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct DriveItemVersionPayload {
    pub site_id: SiteId,
    pub drive_id: DriveId,
    pub list_id: ListId,
    pub item_id: DriveItemId,
    pub version_id: ItemVersionId,
    pub modified_at_epoch_seconds: u64,
    pub version_digest: Digest,
    pub permission_digest: Digest,
}

#[derive(Clone, Debug)]
pub struct DriveItemDeltaPayload {
    pub site_id: SiteId,
    pub drive_id: DriveId,
    pub list_id: ListId,
    pub item_id: DriveItemId,
    pub change: DeltaChange,
    pub item_digest: Digest,
    pub version: Option<ItemVersionId>,
    pub permission_digest: Digest,
}

#[derive(Clone)]
pub enum MicrosoftGraphResponseBody {
    Metadata(DriveItemMetadataPayload),
    Children {
        items: Vec<DriveItemMetadataPayload>,
        next_link: Option<OpaqueGraphNextLink>,
    },
    Search {
        hits: Vec<DriveItemSearchPayload>,
        next_link: Option<OpaqueGraphNextLink>,
    },
    Versions {
        versions: Vec<DriveItemVersionPayload>,
        next_link: Option<OpaqueGraphNextLink>,
    },
    Delta {
        entries: Vec<DriveItemDeltaPayload>,
        next_link: Option<OpaqueGraphNextLink>,
    },
}

impl fmt::Debug for MicrosoftGraphResponseBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Metadata(payload) => formatter.debug_tuple("Metadata").field(payload).finish(),
            Self::Children { items, next_link } => formatter
                .debug_struct("Children")
                .field("item_count", &items.len())
                .field(
                    "next_link",
                    &next_link.as_ref().map(OpaqueGraphNextLink::digest),
                )
                .finish(),
            Self::Search { hits, next_link } => formatter
                .debug_struct("Search")
                .field("hit_count", &hits.len())
                .field(
                    "next_link",
                    &next_link.as_ref().map(OpaqueGraphNextLink::digest),
                )
                .finish(),
            Self::Versions {
                versions,
                next_link,
            } => formatter
                .debug_struct("Versions")
                .field("version_count", &versions.len())
                .field(
                    "next_link",
                    &next_link.as_ref().map(OpaqueGraphNextLink::digest),
                )
                .finish(),
            Self::Delta { entries, next_link } => formatter
                .debug_struct("Delta")
                .field("entry_count", &entries.len())
                .field(
                    "next_link",
                    &next_link.as_ref().map(OpaqueGraphNextLink::digest),
                )
                .finish(),
        }
    }
}

impl MicrosoftGraphResponseBody {
    pub fn operation(&self) -> SharePointGraphOperation {
        match self {
            Self::Metadata(_) => SharePointGraphOperation::DriveItemMetadata,
            Self::Children { .. } => SharePointGraphOperation::DriveItemChildren,
            Self::Search { .. } => SharePointGraphOperation::DriveItemSearch,
            Self::Versions { .. } => SharePointGraphOperation::DriveItemVersions,
            Self::Delta { .. } => SharePointGraphOperation::DriveItemDelta,
        }
    }

    pub fn next_link(&self) -> Option<&OpaqueGraphNextLink> {
        match self {
            Self::Metadata(_) => None,
            Self::Children { next_link, .. }
            | Self::Search { next_link, .. }
            | Self::Versions { next_link, .. }
            | Self::Delta { next_link, .. } => next_link.as_ref(),
        }
    }

    fn digest(&self) -> Digest {
        match self {
            Self::Metadata(payload) => digest_parts([
                payload.site_id.as_ref(),
                payload.drive_id.as_ref(),
                payload.list_id.as_ref(),
                payload.item_id.as_ref(),
                payload.parent_item_id.as_ref().map_or("", AsRef::as_ref),
                payload.name.as_str(),
                &format!("{:?}", payload.kind),
                &payload.size_bytes.unwrap_or_default().to_string(),
                payload.e_tag.as_str(),
                payload.version.as_ref(),
                payload.permission_digest.as_str(),
                &payload.has_download_url.to_string(),
            ]),
            Self::Children { items, next_link } => {
                let mut parts = vec![String::from("children")];
                parts.extend(items.iter().flat_map(payload_digest_parts));
                if let Some(next_link) = next_link {
                    parts.push(next_link.digest().to_owned());
                }
                sha256_digest(parts.join("\0").as_bytes())
            }
            Self::Search { hits, next_link } => {
                let mut parts = vec![String::from("search")];
                parts.extend(hits.iter().flat_map(search_payload_digest_parts));
                if let Some(next_link) = next_link {
                    parts.push(next_link.digest().to_owned());
                }
                sha256_digest(parts.join("\0").as_bytes())
            }
            Self::Versions {
                versions,
                next_link,
            } => {
                let mut parts = vec![String::from("versions")];
                parts.extend(versions.iter().flat_map(version_payload_digest_parts));
                if let Some(next_link) = next_link {
                    parts.push(next_link.digest().to_owned());
                }
                sha256_digest(parts.join("\0").as_bytes())
            }
            Self::Delta { entries, next_link } => {
                let mut parts = vec![String::from("delta")];
                parts.extend(entries.iter().flat_map(delta_payload_digest_parts));
                if let Some(next_link) = next_link {
                    parts.push(next_link.digest().to_owned());
                }
                sha256_digest(parts.join("\0").as_bytes())
            }
        }
    }
}

fn payload_digest_parts(payload: &DriveItemMetadataPayload) -> Vec<String> {
    vec![
        payload.site_id.to_string(),
        payload.drive_id.to_string(),
        payload.list_id.to_string(),
        payload.item_id.to_string(),
        payload
            .parent_item_id
            .as_ref()
            .map_or_else(String::new, ToString::to_string),
        payload.name.clone(),
        format!("{:?}", payload.kind),
        payload.size_bytes.unwrap_or_default().to_string(),
        payload.e_tag.clone(),
        payload.version.to_string(),
        payload.permission_digest.clone(),
        payload.has_download_url.to_string(),
    ]
}

fn search_payload_digest_parts(payload: &DriveItemSearchPayload) -> Vec<String> {
    vec![
        payload.site_id.to_string(),
        payload.drive_id.to_string(),
        payload.list_id.to_string(),
        payload.item_id.to_string(),
        payload.name.clone(),
        payload.path.clone(),
        payload.version.to_string(),
        payload.rank.to_string(),
        payload.permission_digest.clone(),
    ]
}

fn version_payload_digest_parts(payload: &DriveItemVersionPayload) -> Vec<String> {
    vec![
        payload.site_id.to_string(),
        payload.drive_id.to_string(),
        payload.list_id.to_string(),
        payload.item_id.to_string(),
        payload.version_id.to_string(),
        payload.modified_at_epoch_seconds.to_string(),
        payload.version_digest.clone(),
        payload.permission_digest.clone(),
    ]
}

fn delta_payload_digest_parts(payload: &DriveItemDeltaPayload) -> Vec<String> {
    vec![
        payload.site_id.to_string(),
        payload.drive_id.to_string(),
        payload.list_id.to_string(),
        payload.item_id.to_string(),
        format!("{:?}", payload.change),
        payload.item_digest.clone(),
        payload
            .version
            .as_ref()
            .map_or_else(String::new, ToString::to_string),
        payload.permission_digest.clone(),
    ]
}

#[derive(Clone)]
pub struct MicrosoftGraphResponse {
    pub operation: SharePointGraphOperation,
    pub status: u16,
    pub api_version: String,
    pub provider_revision: String,
    pub response_size: usize,
    pub response_digest: Digest,
    pub body: MicrosoftGraphResponseBody,
}

impl fmt::Debug for MicrosoftGraphResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MicrosoftGraphResponse")
            .field("operation", &self.operation)
            .field("status", &self.status)
            .field("api_version", &self.api_version)
            .field("provider_revision", &self.provider_revision)
            .field("response_size", &self.response_size)
            .field("response_digest", &self.response_digest)
            .field("body", &self.body)
            .finish()
    }
}

impl MicrosoftGraphResponse {
    pub fn new(
        request: &MicrosoftGraphRequest,
        status: u16,
        body: MicrosoftGraphResponseBody,
        response_size: usize,
    ) -> Result<Self, SharePointTransportError> {
        if response_size > MAX_RESPONSE_BYTES {
            return Err(SharePointTransportError::Truncated);
        }
        if body.operation() != request.operation {
            return Err(SharePointTransportError::Decode);
        }
        Ok(Self {
            operation: request.operation,
            status,
            api_version: GRAPH_API_VERSION.to_owned(),
            provider_revision: SHAREPOINT_PROVIDER_REVISION.to_owned(),
            response_size,
            response_digest: body.digest(),
            body,
        })
    }

    #[must_use]
    pub fn with_api_version(mut self, api_version: impl Into<String>) -> Self {
        self.api_version = api_version.into();
        self
    }

    #[must_use]
    pub fn with_provider_revision(mut self, provider_revision: impl Into<String>) -> Self {
        self.provider_revision = provider_revision.into();
        self
    }

    pub fn next_link(&self) -> Option<&OpaqueGraphNextLink> {
        self.body.next_link()
    }

    pub fn next_link_digest(&self) -> Option<Digest> {
        self.next_link().map(|value| value.digest().to_owned())
    }
}

#[derive(Clone, Default)]
pub struct SharePointFixture {
    responses: VecDeque<Result<MicrosoftGraphResponse, SharePointTransportError>>,
}

impl fmt::Debug for SharePointFixture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SharePointFixture")
            .field("response_count", &self.responses.len())
            .finish()
    }
}

impl SharePointFixture {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_response(&mut self, response: MicrosoftGraphResponse) {
        self.responses.push_back(Ok(response));
    }

    pub fn push_failure(&mut self, failure: SharePointTransportError) {
        self.responses.push_back(Err(failure));
    }

    pub fn from_responses(
        responses: impl IntoIterator<Item = Result<MicrosoftGraphResponse, SharePointTransportError>>,
    ) -> Self {
        Self {
            responses: responses.into_iter().collect(),
        }
    }
}

/// Layer 1 transport seam. No implementation performs native HTTPS.
pub trait MicrosoftGraphSharePointTransport: fmt::Debug + Send {
    fn execute(
        &mut self,
        request: &MicrosoftGraphRequest,
    ) -> Result<MicrosoftGraphResponse, SharePointTransportError>;

    fn provenance(&self) -> ProviderProvenance;

    fn requests(&self) -> Vec<SharePointRequestReceipt>;
}

pub use MicrosoftGraphSharePointTransport as SharePointTransport;

#[derive(Clone)]
struct ScriptedTransportState {
    responses: VecDeque<Result<MicrosoftGraphResponse, SharePointTransportError>>,
    requests: Vec<SharePointRequestReceipt>,
    failure: Option<SharePointTransportError>,
}

impl fmt::Debug for ScriptedTransportState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScriptedTransportState")
            .field("queued_responses", &self.responses.len())
            .field("requests", &self.requests.len())
            .field("configured_failure", &self.failure)
            .finish()
    }
}

macro_rules! scripted_transport {
    ($name:ident, $provenance:expr) => {
        #[derive(Clone)]
        pub struct $name {
            state: Arc<Mutex<ScriptedTransportState>>,
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("provenance", &$provenance)
                    .field(
                        "state",
                        &self.state.lock().expect("transport state lock").clone(),
                    )
                    .finish()
            }
        }

        impl $name {
            pub fn new(
                responses: impl IntoIterator<
                    Item = Result<MicrosoftGraphResponse, SharePointTransportError>,
                >,
            ) -> Self {
                Self {
                    state: Arc::new(Mutex::new(ScriptedTransportState {
                        responses: responses.into_iter().collect(),
                        requests: Vec::new(),
                        failure: None,
                    })),
                }
            }

            pub fn from_fixture(fixture: SharePointFixture) -> Self {
                Self::new(fixture.responses)
            }

            #[must_use]
            pub fn with_failure(self, failure: SharePointTransportError) -> Self {
                self.set_failure(failure);
                self
            }

            pub fn set_failure(&self, failure: SharePointTransportError) {
                self.state.lock().expect("transport state lock").failure = Some(failure);
            }

            pub fn clear_failure(&self) {
                self.state.lock().expect("transport state lock").failure = None;
            }

            pub fn requests(&self) -> Vec<SharePointRequestReceipt> {
                self.state
                    .lock()
                    .expect("transport state lock")
                    .requests
                    .clone()
            }
        }

        impl MicrosoftGraphSharePointTransport for $name {
            fn execute(
                &mut self,
                request: &MicrosoftGraphRequest,
            ) -> Result<MicrosoftGraphResponse, SharePointTransportError> {
                let mut state = self.state.lock().expect("transport state lock");
                state
                    .requests
                    .push(SharePointRequestReceipt::from_request(request));
                if let Some(failure) = &state.failure {
                    return Err(failure.clone());
                }
                state
                    .responses
                    .pop_front()
                    .unwrap_or(Err(SharePointTransportError::Network))
            }

            fn provenance(&self) -> ProviderProvenance {
                $provenance
            }

            fn requests(&self) -> Vec<SharePointRequestReceipt> {
                self.requests()
            }
        }
    };
}

scripted_transport!(RecordingSharePointTransport, ProviderProvenance::Recording);
scripted_transport!(FixtureSharePointTransport, ProviderProvenance::Fixture);
scripted_transport!(LoopbackSharePointTransport, ProviderProvenance::Loopback);

pub type FakeSharePointTransport = FixtureSharePointTransport;
pub type RecordingMicrosoftGraphTransport = RecordingSharePointTransport;

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvTransport;

impl MicrosoftGraphSharePointTransport for BlockedEnvTransport {
    fn execute(
        &mut self,
        _request: &MicrosoftGraphRequest,
    ) -> Result<MicrosoftGraphResponse, SharePointTransportError> {
        Err(SharePointTransportError::BlockedEnv)
    }

    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }

    fn requests(&self) -> Vec<SharePointRequestReceipt> {
        Vec::new()
    }
}

pub fn native_probe_from_environment() -> crate::model::NativeProbe {
    crate::model::NativeProbe {
        status: crate::model::NativeProbeStatus::BlockedEnv,
        native_connected_claim: false,
    }
}

#[allow(dead_code)]
fn _transport_redaction_markers(
    request: &MicrosoftGraphRequest,
    response: &MicrosoftGraphResponse,
    search: &SharePointSearchRequest,
) {
    let _ = canonical_digest(request);
    let _ = response.response_digest.as_str();
    let _ = search.query.digest();
}
