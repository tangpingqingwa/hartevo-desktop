//! Provider and transport seams for the three bounded Azure ARM reads.
//!
//! Layer 1 has no HTTP client, Entra resolver, Azure SDK, deploy path,
//! revision lifecycle mutation, traffic/scale mutation, exec, or log
//! download. A later Layer 2 host may implement the transport trait.

use std::{collections::VecDeque, fmt, marker::PhantomData};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};
use zeroize::Zeroize;

use crate::error::{
    AzureContainerAppsRevisionResultError, AzureContainerAppsTransportError, Result,
};
use crate::model::{
    AppMetadata, AzureContainerAppsRevisionScope, Digest, RevisionMetadata, TransportProvenance,
    validate_response_bytes,
};
use crate::{
    API_REVISION, CONTRACT_VERSION, LAYER1_PERMISSIONS, MAX_PAGE_SIZE, MAX_PAGES, PROVIDER_ID,
};

pub type TransportResult<T> = std::result::Result<T, AzureContainerAppsTransportError>;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AzureContainerAppsOperation {
    GetContainerApp,
    GetRevision,
    ListRevisions,
}

impl AzureContainerAppsOperation {
    pub const ALL: [Self; 3] = [
        Self::GetContainerApp,
        Self::GetRevision,
        Self::ListRevisions,
    ];
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GetContainerApp => "GetContainerApp",
            Self::GetRevision => "GetRevision",
            Self::ListRevisions => "ListRevisions",
        }
    }
}

/// The only provider transport interface exposed at Layer 1.
pub trait AzureContainerAppsTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;
    fn get_container_app(
        &mut self,
        request: &GetContainerAppRequest,
    ) -> TransportResult<GetContainerAppResponse>;
    fn get_revision(
        &mut self,
        request: &GetRevisionRequest,
    ) -> TransportResult<GetRevisionResponse>;
    fn list_revisions(
        &mut self,
        request: &ListRevisionsRequest,
    ) -> TransportResult<ListRevisionsResponse>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: AzureContainerAppsOperation,
    pub scope_digest: Digest,
    pub page_digest: Option<Digest>,
    pub request_digest: Digest,
    pub path_digest: Digest,
}

#[derive(Clone, Eq, PartialEq)]
pub struct GetContainerAppRequest {
    scope: AzureContainerAppsRevisionScope,
    request_digest: Digest,
}

impl GetContainerAppRequest {
    pub fn for_scope(scope: &AzureContainerAppsRevisionScope) -> Result<Self> {
        scope.validate()?;
        Ok(Self {
            scope: scope.clone(),
            request_digest: Digest::from_parts(
                "azure-container-apps-get-container-app-request/v1",
                &[
                    ("scope", scope.digest().as_str().to_owned()),
                    ("api", API_REVISION.to_owned()),
                ],
            ),
        })
    }
    pub fn scope(&self) -> &AzureContainerAppsRevisionScope {
        &self.scope
    }
    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }
    pub fn path_digest(&self) -> Digest {
        Digest::from_parts(
            "azure-container-apps-arm-path/v1",
            &[
                (
                    "operation",
                    AzureContainerAppsOperation::GetContainerApp
                        .as_str()
                        .to_owned(),
                ),
                ("scope", self.scope.digest().as_str().to_owned()),
                ("api", API_REVISION.to_owned()),
            ],
        )
    }
    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AzureContainerAppsOperation::GetContainerApp,
            scope_digest: self.scope.digest(),
            page_digest: None,
            request_digest: self.request_digest.clone(),
            path_digest: self.path_digest(),
        }
    }
}

impl fmt::Debug for GetContainerAppRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GetContainerAppRequest")
            .field("scope_digest", &self.scope.digest())
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GetRevisionRequest {
    scope: AzureContainerAppsRevisionScope,
    request_digest: Digest,
}

impl GetRevisionRequest {
    pub fn for_scope(scope: &AzureContainerAppsRevisionScope) -> Result<Self> {
        scope.validate()?;
        Ok(Self {
            scope: scope.clone(),
            request_digest: Digest::from_parts(
                "azure-container-apps-get-revision-request/v1",
                &[
                    ("scope", scope.digest().as_str().to_owned()),
                    ("api", API_REVISION.to_owned()),
                ],
            ),
        })
    }
    pub fn scope(&self) -> &AzureContainerAppsRevisionScope {
        &self.scope
    }
    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }
    pub fn path_digest(&self) -> Digest {
        Digest::from_parts(
            "azure-container-apps-arm-path/v1",
            &[
                (
                    "operation",
                    AzureContainerAppsOperation::GetRevision.as_str().to_owned(),
                ),
                ("scope", self.scope.digest().as_str().to_owned()),
                ("api", API_REVISION.to_owned()),
            ],
        )
    }
    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AzureContainerAppsOperation::GetRevision,
            scope_digest: self.scope.digest(),
            page_digest: None,
            request_digest: self.request_digest.clone(),
            path_digest: self.path_digest(),
        }
    }
}

impl fmt::Debug for GetRevisionRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GetRevisionRequest")
            .field("scope_digest", &self.scope.digest())
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

/// A nextLink is consumed once and retained only as digest material.
#[derive(Clone, Eq, PartialEq)]
pub struct OpaquePageToken {
    token_digest: Digest,
    continuation_digest: Digest,
    scope_digest: Digest,
    page_size: u16,
    page_number: u16,
}

impl OpaquePageToken {
    pub fn from_next_link(
        raw_next_link: impl Into<String>,
        scope: &AzureContainerAppsRevisionScope,
        page_size: u16,
        page_number: u16,
    ) -> Result<Self> {
        let mut raw_next_link = raw_next_link.into();
        if raw_next_link.trim().is_empty()
            || raw_next_link.len() > crate::MAX_NEXT_LINK_BYTES
            || page_number == 0
            || !(1..=MAX_PAGE_SIZE).contains(&page_size)
        {
            raw_next_link.zeroize();
            return Err(AzureContainerAppsRevisionResultError::InvalidText { field: "next-link" });
        }
        let scope_digest = scope.digest();
        let continuation_digest = Digest::from_parts(
            "azure-container-apps-opaque-next-link-continuation/v1",
            &[
                ("value", raw_next_link.clone()),
                ("scope", scope_digest.as_str().to_owned()),
                ("page_size", page_size.to_string()),
            ],
        );
        let token_digest = Digest::from_parts(
            "azure-container-apps-opaque-next-link/v1",
            &[
                ("value", raw_next_link.clone()),
                ("scope", scope_digest.as_str().to_owned()),
                ("page_size", page_size.to_string()),
                ("page_number", page_number.to_string()),
            ],
        );
        raw_next_link.zeroize();
        Ok(Self {
            token_digest,
            continuation_digest,
            scope_digest,
            page_size,
            page_number,
        })
    }

    pub fn from_digest(
        token_digest: Digest,
        scope: &AzureContainerAppsRevisionScope,
        page_size: u16,
        page_number: u16,
    ) -> Result<Self> {
        if page_number == 0 || !(1..=MAX_PAGE_SIZE).contains(&page_size) {
            return Err(AzureContainerAppsRevisionResultError::CursorMismatch);
        }
        let scope_digest = scope.digest();
        let continuation_digest = Digest::from_parts(
            "azure-container-apps-opaque-next-link-continuation/v1",
            &[
                ("token", token_digest.as_str().to_owned()),
                ("scope", scope_digest.as_str().to_owned()),
                ("page_size", page_size.to_string()),
            ],
        );
        let cursor = Self {
            token_digest,
            continuation_digest,
            scope_digest,
            page_size,
            page_number,
        };
        cursor.validate_against(scope, page_size)?;
        Ok(cursor)
    }

    pub fn token_digest(&self) -> &Digest {
        &self.token_digest
    }
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }
    pub fn continuation_digest(&self) -> &Digest {
        &self.continuation_digest
    }
    pub const fn page_size(&self) -> u16 {
        self.page_size
    }
    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub fn validate_against(
        &self,
        scope: &AzureContainerAppsRevisionScope,
        page_size: u16,
    ) -> Result<()> {
        if self.scope_digest != scope.digest()
            || self.page_size != page_size
            || self.page_number == 0
            || self.page_size == 0
            || self.page_size > MAX_PAGE_SIZE
        {
            return Err(AzureContainerAppsRevisionResultError::CursorMismatch);
        }
        self.token_digest.validate()
    }
}

pub type Cursor = OpaquePageToken;

impl Serialize for OpaquePageToken {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("OpaquePageToken", 5)?;
        state.serialize_field("tokenDigest", &self.token_digest)?;
        state.serialize_field("continuationDigest", &self.continuation_digest)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("pageSize", &self.page_size)?;
        state.serialize_field("pageNumber", &self.page_number)?;
        state.end()
    }
}

impl fmt::Debug for OpaquePageToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaquePageToken")
            .field("token_digest", &self.token_digest)
            .field("continuation_digest", &self.continuation_digest)
            .field("scope_digest", &self.scope_digest)
            .field("page_size", &self.page_size)
            .field("page_number", &self.page_number)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ListRevisionsRequest {
    scope: AzureContainerAppsRevisionScope,
    page_size: u16,
    page_number: u16,
    cursor: Option<OpaquePageToken>,
    request_digest: Digest,
}

impl ListRevisionsRequest {
    pub fn new(
        scope: &AzureContainerAppsRevisionScope,
        page_size: u16,
        cursor: Option<OpaquePageToken>,
    ) -> Result<Self> {
        scope.validate()?;
        if !(1..=MAX_PAGE_SIZE).contains(&page_size) {
            return Err(AzureContainerAppsRevisionResultError::InvalidText { field: "page-size" });
        }
        let page_number = cursor.as_ref().map_or(1, OpaquePageToken::page_number);
        if let Some(cursor) = &cursor {
            cursor.validate_against(scope, page_size)?;
        }
        let request_digest = Digest::from_parts(
            "azure-container-apps-list-revisions-request/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("api", API_REVISION.to_owned()),
                ("page_size", page_size.to_string()),
                ("page_number", page_number.to_string()),
                (
                    "cursor",
                    cursor.as_ref().map_or_else(String::new, |value| {
                        value.token_digest().as_str().to_owned()
                    }),
                ),
            ],
        );
        Ok(Self {
            scope: scope.clone(),
            page_size,
            page_number,
            cursor,
            request_digest,
        })
    }
    pub fn first(scope: &AzureContainerAppsRevisionScope, page_size: u16) -> Result<Self> {
        Self::new(scope, page_size, None)
    }
    pub fn scope(&self) -> &AzureContainerAppsRevisionScope {
        &self.scope
    }
    pub const fn page_size(&self) -> u16 {
        self.page_size
    }
    pub const fn page_number(&self) -> u16 {
        self.page_number
    }
    pub fn cursor(&self) -> Option<&OpaquePageToken> {
        self.cursor.as_ref()
    }
    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }
    pub fn path_digest(&self) -> Digest {
        Digest::from_parts(
            "azure-container-apps-arm-path/v1",
            &[
                (
                    "operation",
                    AzureContainerAppsOperation::ListRevisions
                        .as_str()
                        .to_owned(),
                ),
                ("scope", self.scope.digest().as_str().to_owned()),
                ("api", API_REVISION.to_owned()),
                ("page_size", self.page_size.to_string()),
                ("page_number", self.page_number.to_string()),
                (
                    "cursor",
                    self.cursor.as_ref().map_or_else(String::new, |value| {
                        value.token_digest().as_str().to_owned()
                    }),
                ),
            ],
        )
    }
    pub fn recorded_request(&self) -> RecordedRequest {
        RecordedRequest {
            operation: AzureContainerAppsOperation::ListRevisions,
            scope_digest: self.scope.digest(),
            page_digest: self
                .cursor
                .as_ref()
                .map(|value| value.token_digest().clone()),
            request_digest: self.request_digest.clone(),
            path_digest: self.path_digest(),
        }
    }
}

impl fmt::Debug for ListRevisionsRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListRevisionsRequest")
            .field("scope_digest", &self.scope.digest())
            .field("page_size", &self.page_size)
            .field("page_number", &self.page_number)
            .field("cursor", &self.cursor)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetContainerAppResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub metadata: AppMetadata,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl GetContainerAppResponse {
    pub fn new(
        request: &GetContainerAppRequest,
        metadata: AppMetadata,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        metadata.validate_against(request.scope())?;
        let mut response = Self {
            scope_digest: request.scope().digest(),
            request_digest: request.request_digest().clone(),
            metadata,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-azure-container-app-response"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }
    #[must_use]
    pub fn with_declared_digest(mut self, evidence_digest: Digest) -> Self {
        self.evidence_digest = evidence_digest;
        self
    }
    pub fn validate_integrity(&self, request: &GetContainerAppRequest) -> Result<()> {
        if validate_response_bytes(self.response_bytes).is_err()
            || self.scope_digest != request.scope().digest()
            || self.request_digest != *request.request_digest()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_connected()
            || self.provenance.is_native()
            || self.provenance.is_first_party()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AzureContainerAppsRevisionResultError::TamperedEvidence);
        }
        self.metadata.validate_against(request.scope())
    }
    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "azure-container-apps-get-container-app-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("metadata", self.metadata.digest().as_str().to_owned()),
                ("response_bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetRevisionResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub metadata: RevisionMetadata,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl GetRevisionResponse {
    pub fn new(
        request: &GetRevisionRequest,
        metadata: RevisionMetadata,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        metadata.validate_against(request.scope())?;
        let mut response = Self {
            scope_digest: request.scope().digest(),
            request_digest: request.request_digest().clone(),
            metadata,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-azure-container-app-revision-response"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }
    #[must_use]
    pub fn with_declared_digest(mut self, evidence_digest: Digest) -> Self {
        self.evidence_digest = evidence_digest;
        self
    }
    pub fn validate_integrity(&self, request: &GetRevisionRequest) -> Result<()> {
        if validate_response_bytes(self.response_bytes).is_err()
            || self.scope_digest != request.scope().digest()
            || self.request_digest != *request.request_digest()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_connected()
            || self.provenance.is_native()
            || self.provenance.is_first_party()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AzureContainerAppsRevisionResultError::TamperedEvidence);
        }
        self.metadata.validate_against(request.scope())
    }
    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "azure-container-apps-get-revision-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("metadata", self.metadata.digest().as_str().to_owned()),
                ("response_bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListRevisionsResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub page_number: u16,
    pub page_size: u16,
    pub revisions: Vec<RevisionMetadata>,
    pub next_cursor: Option<OpaquePageToken>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}

impl ListRevisionsResponse {
    pub fn new(
        request: &ListRevisionsRequest,
        revisions: Vec<RevisionMetadata>,
        raw_next_link: Option<String>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        if revisions.len() > request.page_size() as usize {
            return Err(AzureContainerAppsRevisionResultError::PartialEvidence);
        }
        for revision in &revisions {
            revision.validate_list_item_against(request.scope())?;
        }
        let next_cursor = raw_next_link
            .map(|next_link| {
                OpaquePageToken::from_next_link(
                    next_link,
                    request.scope(),
                    request.page_size(),
                    request.page_number().saturating_add(1),
                )
            })
            .transpose()?;
        let mut response = Self {
            scope_digest: request.scope().digest(),
            request_digest: request.request_digest().clone(),
            page_number: request.page_number(),
            page_size: request.page_size(),
            revisions,
            next_cursor,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-azure-container-app-list-response"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }
    pub fn single(
        request: &ListRevisionsRequest,
        revision: RevisionMetadata,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        Self::new(request, vec![revision], None, response_bytes, provenance)
    }
    #[must_use]
    pub fn with_declared_digest(mut self, evidence_digest: Digest) -> Self {
        self.evidence_digest = evidence_digest;
        self
    }
    pub fn has_more(&self) -> bool {
        self.next_cursor.is_some()
    }
    pub fn validate_integrity(&self, request: &ListRevisionsRequest) -> Result<()> {
        if validate_response_bytes(self.response_bytes).is_err()
            || self.scope_digest != request.scope().digest()
            || self.request_digest != *request.request_digest()
            || self.page_number != request.page_number()
            || self.page_size != request.page_size()
            || self.revisions.len() > request.page_size() as usize
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_connected()
            || self.provenance.is_native()
            || self.provenance.is_first_party()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AzureContainerAppsRevisionResultError::TamperedEvidence);
        }
        if let Some(cursor) = &self.next_cursor {
            cursor.validate_against(request.scope(), request.page_size())?;
            if cursor.page_number() != request.page_number().saturating_add(1) {
                return Err(AzureContainerAppsRevisionResultError::CursorMismatch);
            }
        }
        for revision in &self.revisions {
            revision.validate_list_item_against(request.scope())?;
        }
        Ok(())
    }
    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "azure-container-apps-list-revisions-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("page", self.page_number.to_string()),
                ("page_size", self.page_size.to_string()),
                (
                    "revisions",
                    self.revisions
                        .iter()
                        .map(RevisionMetadata::digest)
                        .map(|digest| digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
                (
                    "cursor",
                    self.next_cursor.as_ref().map_or_else(String::new, |value| {
                        value.token_digest().as_str().to_owned()
                    }),
                ),
                ("response_bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AzureContainerAppsProviderDefinition {
    provider_id: String,
    provider_revision: u64,
    api_revision: String,
    contract_version: String,
    release: String,
    provenance: TransportProvenance,
    capability_digest: Digest,
    provider_digest: Digest,
    connected: bool,
    native: bool,
    first_party: bool,
}

impl AzureContainerAppsProviderDefinition {
    pub fn new(
        provider_revision: u64,
        release: impl Into<String>,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        let release = release.into();
        if provider_revision == 0
            || release.is_empty()
            || release.len() > 128
            || release.chars().any(char::is_control)
        {
            return Err(AzureContainerAppsRevisionResultError::ProviderDrift);
        }
        let capability_digest = Digest::from_parts(
            "azure-container-apps-provider-capabilities/v1",
            &LAYER1_PERMISSIONS
                .iter()
                .map(|permission| ("permission", (*permission).to_owned()))
                .collect::<Vec<_>>(),
        );
        let provider_digest =
            Self::calculate_digest(provider_revision, &release, provenance, &capability_digest);
        Ok(Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_revision,
            api_revision: API_REVISION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            release,
            provenance,
            capability_digest,
            provider_digest,
            connected: false,
            native: false,
            first_party: false,
        })
    }
    pub fn recording(provider_revision: u64, release: impl Into<String>) -> Result<Self> {
        Self::new(provider_revision, release, TransportProvenance::Recording)
    }
    fn calculate_digest(
        provider_revision: u64,
        release: &str,
        provenance: TransportProvenance,
        capability_digest: &Digest,
    ) -> Digest {
        Digest::from_parts(
            "azure-container-apps-provider/v1",
            &[
                ("provider_id", PROVIDER_ID.to_owned()),
                ("provider_revision", provider_revision.to_string()),
                ("api_revision", API_REVISION.to_owned()),
                ("contract_version", CONTRACT_VERSION.to_owned()),
                ("release", release.to_owned()),
                ("provenance", provenance.as_str().to_owned()),
                ("capability", capability_digest.as_str().to_owned()),
            ],
        )
    }
    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }
    pub const fn provider_revision(&self) -> u64 {
        self.provider_revision
    }
    pub fn api_revision(&self) -> &str {
        &self.api_revision
    }
    pub fn contract_version(&self) -> &str {
        &self.contract_version
    }
    pub fn release(&self) -> &str {
        &self.release
    }
    pub const fn provenance(&self) -> TransportProvenance {
        self.provenance
    }
    pub fn capability_digest(&self) -> &Digest {
        &self.capability_digest
    }
    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }
    pub const fn connected(&self) -> bool {
        self.connected
    }
    pub const fn native(&self) -> bool {
        self.native
    }
    pub const fn first_party(&self) -> bool {
        self.first_party
    }
    #[must_use]
    pub fn with_declared_digest(mut self, provider_digest: Digest) -> Self {
        self.provider_digest = provider_digest;
        self
    }
    pub fn validate(&self) -> Result<()> {
        if self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.api_revision != API_REVISION
            || self.contract_version != CONTRACT_VERSION
            || self.release.is_empty()
            || self.connected
            || self.native
            || self.first_party
            || self.provenance.is_connected()
            || self.provenance.is_native()
            || self.provenance.is_first_party()
            || self.capability_digest.validate().is_err()
            || self.provider_digest
                != Self::calculate_digest(
                    self.provider_revision,
                    &self.release,
                    self.provenance,
                    &self.capability_digest,
                )
        {
            Err(AzureContainerAppsRevisionResultError::ProviderDrift)
        } else {
            Ok(())
        }
    }
}

impl Serialize for AzureContainerAppsProviderDefinition {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AzureContainerAppsProviderDefinition", 11)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("apiRevision", &self.api_revision)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("release", &self.release)?;
        state.serialize_field("provenance", &self.provenance)?;
        state.serialize_field("capabilityDigest", &self.capability_digest)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("connected", &self.connected)?;
        state.serialize_field("native", &self.native)?;
        state.serialize_field("firstParty", &self.first_party)?;
        state.end()
    }
}

pub struct AzureContainerAppsProvider<T> {
    transport: T,
    definition: AzureContainerAppsProviderDefinition,
}

impl<T: fmt::Debug> fmt::Debug for AzureContainerAppsProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AzureContainerAppsProvider")
            .field("definition", &self.definition)
            .field("transport", &self.transport)
            .finish()
    }
}

impl<T: AzureContainerAppsTransport> AzureContainerAppsProvider<T> {
    pub fn new(transport: T, provider_revision: u64, release: impl Into<String>) -> Result<Self> {
        let provenance = transport.provenance();
        Ok(Self {
            definition: AzureContainerAppsProviderDefinition::new(
                provider_revision,
                release,
                provenance,
            )?,
            transport,
        })
    }
    pub fn recording(transport: T) -> Result<Self> {
        Self::new(transport, 1, "1.0.0")
    }
    pub fn definition(&self) -> &AzureContainerAppsProviderDefinition {
        &self.definition
    }
    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }
    pub fn transport(&self) -> &T {
        &self.transport
    }
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }
    pub fn get_container_app(
        &mut self,
        request: &GetContainerAppRequest,
    ) -> TransportResult<GetContainerAppResponse> {
        self.transport.get_container_app(request)
    }
    pub fn get_revision(
        &mut self,
        request: &GetRevisionRequest,
    ) -> TransportResult<GetRevisionResponse> {
        self.transport.get_revision(request)
    }
    pub fn list_revisions(
        &mut self,
        request: &ListRevisionsRequest,
    ) -> TransportResult<ListRevisionsResponse> {
        self.transport.list_revisions(request)
    }
}

pub trait ProvenanceMarker: fmt::Debug + Send + Sync + 'static {
    const PROVENANCE: TransportProvenance;
}
#[derive(Clone, Copy, Debug)]
pub struct FixtureMarker;
impl ProvenanceMarker for FixtureMarker {
    const PROVENANCE: TransportProvenance = TransportProvenance::Fixture;
}
#[derive(Clone, Copy, Debug)]
pub struct RecordingMarker;
impl ProvenanceMarker for RecordingMarker {
    const PROVENANCE: TransportProvenance = TransportProvenance::Recording;
}
#[derive(Clone, Copy, Debug)]
pub struct FakeMarker;
impl ProvenanceMarker for FakeMarker {
    const PROVENANCE: TransportProvenance = TransportProvenance::Fake;
}
#[derive(Clone, Copy, Debug)]
pub struct LoopbackMarker;
impl ProvenanceMarker for LoopbackMarker {
    const PROVENANCE: TransportProvenance = TransportProvenance::Loopback;
}

#[derive(Clone, Debug)]
pub struct ScriptedTransport<M: ProvenanceMarker> {
    app_responses: VecDeque<TransportResult<GetContainerAppResponse>>,
    revision_responses: VecDeque<TransportResult<GetRevisionResponse>>,
    list_responses: VecDeque<TransportResult<ListRevisionsResponse>>,
    recorded_requests: Vec<RecordedRequest>,
    marker: PhantomData<M>,
}

impl<M: ProvenanceMarker> Default for ScriptedTransport<M> {
    fn default() -> Self {
        Self {
            app_responses: VecDeque::new(),
            revision_responses: VecDeque::new(),
            list_responses: VecDeque::new(),
            recorded_requests: Vec::new(),
            marker: PhantomData,
        }
    }
}

impl<M: ProvenanceMarker> ScriptedTransport<M> {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn push_app_response(&mut self, response: TransportResult<GetContainerAppResponse>) {
        self.app_responses.push_back(response);
    }
    pub fn push_get_container_app_response(
        &mut self,
        response: TransportResult<GetContainerAppResponse>,
    ) {
        self.push_app_response(response);
    }
    pub fn push_revision_response(&mut self, response: TransportResult<GetRevisionResponse>) {
        self.revision_responses.push_back(response);
    }
    pub fn push_get_revision_response(&mut self, response: TransportResult<GetRevisionResponse>) {
        self.push_revision_response(response);
    }
    pub fn push_list_response(&mut self, response: TransportResult<ListRevisionsResponse>) {
        self.list_responses.push_back(response);
    }
    pub fn push_list_revisions_response(
        &mut self,
        response: TransportResult<ListRevisionsResponse>,
    ) {
        self.push_list_response(response);
    }
    pub fn recorded_requests(&self) -> &[RecordedRequest] {
        &self.recorded_requests
    }

    pub fn for_scope(
        scope: &AzureContainerAppsRevisionScope,
        observed_at: DateTime<Utc>,
    ) -> Result<Self> {
        let app_request = GetContainerAppRequest::for_scope(scope)?;
        let app_metadata = AppMetadata::from_provider(
            scope,
            crate::model::AppProvisioningState::Succeeded,
            Some(scope.revision().as_str().to_owned()),
        )?;
        let app_response =
            GetContainerAppResponse::new(&app_request, app_metadata, 512, M::PROVENANCE)?;
        let revision_request = GetRevisionRequest::for_scope(scope)?;
        let revision_metadata = RevisionMetadata::for_scope(
            scope,
            true,
            crate::model::RevisionHealthState::Healthy,
            crate::model::RevisionProvisioningState::Provisioned,
            crate::model::RevisionRunningState::Running,
            Some(observed_at),
            Some(observed_at),
            1,
            100,
        )?;
        let revision_response = GetRevisionResponse::new(
            &revision_request,
            revision_metadata.clone(),
            768,
            M::PROVENANCE,
        )?;
        let list_request = ListRevisionsRequest::first(scope, 10)?;
        let list_response =
            ListRevisionsResponse::single(&list_request, revision_metadata, 1_024, M::PROVENANCE)?;
        let mut transport = Self::new();
        transport.push_app_response(Ok(app_response));
        transport.push_list_response(Ok(list_response));
        transport.push_revision_response(Ok(revision_response));
        Ok(transport)
    }
}

impl<M: ProvenanceMarker> AzureContainerAppsTransport for ScriptedTransport<M> {
    fn provenance(&self) -> TransportProvenance {
        M::PROVENANCE
    }
    fn get_container_app(
        &mut self,
        request: &GetContainerAppRequest,
    ) -> TransportResult<GetContainerAppResponse> {
        self.recorded_requests.push(request.recorded_request());
        self.app_responses
            .pop_front()
            .unwrap_or(Err(AzureContainerAppsTransportError::InvalidResponse))
    }
    fn get_revision(
        &mut self,
        request: &GetRevisionRequest,
    ) -> TransportResult<GetRevisionResponse> {
        self.recorded_requests.push(request.recorded_request());
        self.revision_responses
            .pop_front()
            .unwrap_or(Err(AzureContainerAppsTransportError::InvalidResponse))
    }
    fn list_revisions(
        &mut self,
        request: &ListRevisionsRequest,
    ) -> TransportResult<ListRevisionsResponse> {
        self.recorded_requests.push(request.recorded_request());
        self.list_responses
            .pop_front()
            .unwrap_or(Err(AzureContainerAppsTransportError::InvalidResponse))
    }
}

pub type FixtureTransport = ScriptedTransport<FixtureMarker>;
pub type RecordingTransport = ScriptedTransport<RecordingMarker>;
pub type FakeTransport = ScriptedTransport<FakeMarker>;
pub type LoopbackTransport = ScriptedTransport<LoopbackMarker>;

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvTransport;

impl AzureContainerAppsTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }
    fn get_container_app(
        &mut self,
        _request: &GetContainerAppRequest,
    ) -> TransportResult<GetContainerAppResponse> {
        Err(AzureContainerAppsTransportError::BlockedEnv)
    }
    fn get_revision(
        &mut self,
        _request: &GetRevisionRequest,
    ) -> TransportResult<GetRevisionResponse> {
        Err(AzureContainerAppsTransportError::BlockedEnv)
    }
    fn list_revisions(
        &mut self,
        _request: &ListRevisionsRequest,
    ) -> TransportResult<ListRevisionsResponse> {
        Err(AzureContainerAppsTransportError::BlockedEnv)
    }
}

pub type GetAppRequest = GetContainerAppRequest;
pub type GetAppResponse = GetContainerAppResponse;
pub type ListRevisionRequest = ListRevisionsRequest;
pub type ListRevisionResponse = ListRevisionsResponse;
pub const MAX_PROVIDER_PAGES: u16 = MAX_PAGES;
