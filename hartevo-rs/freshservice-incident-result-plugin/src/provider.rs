//! Provider definitions and non-native transport seams.

use std::{collections::VecDeque, fmt};

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use thiserror::Error;

use crate::error::{FreshserviceIncidentResultError, Result};
use crate::model::{
    AssetLifecycle, AssetMetadata, ChangeMetadata, ChangeRisk, ChangeStatus, ChangeWindowMetadata,
    Digest, FreshserviceIncidentResultScope, IncidentMetadata, IncidentPriority, IncidentStatus,
    TransportProvenance,
};
use crate::{
    MAX_PAGE_SIZE, MAX_PAGES, MAX_RECORDS_PER_KIND, MAX_RESPONSE_BYTES, PROVIDER_API_REVISION,
    PROVIDER_ID,
};

#[derive(Clone, Debug, Eq, Error, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "details")]
pub enum FreshserviceTransportError {
    #[error("provider denied the bounded read")]
    Denied,
    #[error("provider access was lost")]
    AccessLoss,
    #[error("bounded record was not found")]
    NotFound,
    #[error("provider rate limited the bounded read")]
    RateLimited { retry_after_seconds: u32 },
    #[error("provider response is unknown")]
    ProviderUnknown,
    #[error("provider response was malformed")]
    MalformedResponse,
    #[error("provider response exceeded the bound")]
    ResponseTooLarge,
    #[error("environment blocks provider transport")]
    BlockedEnv,
    #[error("provider revision is stale")]
    StaleRevision,
    #[error("provider response failed integrity validation")]
    TamperedResponse,
}

impl FreshserviceTransportError {
    pub const fn is_non_adoptable(&self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FreshserviceProviderDefinition {
    pub id: String,
    pub api_revision: String,
    pub operations: Vec<String>,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub provider_digest: Digest,
}

impl FreshserviceProviderDefinition {
    pub fn for_provenance(provenance: TransportProvenance) -> Self {
        let mut definition = Self {
            id: PROVIDER_ID.to_owned(),
            api_revision: PROVIDER_API_REVISION.to_owned(),
            operations: vec![
                "GET /api/v2/incidents/:id".to_owned(),
                "GET /api/v2/changes/:id".to_owned(),
                "GET /api/v2/assets/:id".to_owned(),
            ],
            provenance,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            provider_digest: Digest::from_text("unsealed-freshservice-provider"),
        };
        definition.provider_digest = definition.calculate_digest();
        definition
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "freshservice-provider/v1",
            &[
                ("id", self.id.clone()),
                ("api_revision", self.api_revision.clone()),
                ("operations", self.operations.join("\n")),
                ("provenance", self.provenance.as_str().to_owned()),
                ("connected", self.connected.to_string()),
                ("native", self.native.to_string()),
                ("first_party", self.first_party.to_string()),
                ("provider_receipt", self.provider_receipt.to_string()),
            ],
        )
    }

    pub fn validate(&self) -> Result<()> {
        let expected = Self::for_provenance(self.provenance);
        if self.id != expected.id
            || self.api_revision != expected.api_revision
            || self.operations != expected.operations
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provider_digest != expected.provider_digest
        {
            return Err(FreshserviceIncidentResultError::ProviderDefinitionDrift);
        }
        Ok(())
    }

    pub fn digest(&self) -> &Digest {
        &self.provider_digest
    }
}

pub trait FreshserviceTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;
    fn read_incident(&mut self, request: &IncidentRequest) -> Result<IncidentPage>;
    fn read_change(&mut self, request: &ChangeRequest) -> Result<ChangePage>;
    fn read_asset(&mut self, request: &AssetRequest) -> Result<AssetPage>;
}

pub struct FreshserviceProvider<T: FreshserviceTransport> {
    transport: T,
    definition: FreshserviceProviderDefinition,
}

impl<T: FreshserviceTransport> fmt::Debug for FreshserviceProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FreshserviceProvider")
            .field("definition", &self.definition)
            .finish()
    }
}

impl<T: FreshserviceTransport> FreshserviceProvider<T> {
    pub fn new(transport: T) -> Result<Self> {
        let definition = FreshserviceProviderDefinition::for_provenance(transport.provenance());
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn definition(&self) -> &FreshserviceProviderDefinition {
        &self.definition
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.definition.provenance
    }

    pub fn read_incident(&mut self, request: &IncidentRequest) -> Result<IncidentPage> {
        request.validate()?;
        let page = self.transport.read_incident(request)?;
        page.validate_integrity(request)?;
        self.validate_page_provenance(page.provenance)
            .map(|()| page)
    }

    pub fn read_change(&mut self, request: &ChangeRequest) -> Result<ChangePage> {
        request.validate()?;
        let page = self.transport.read_change(request)?;
        page.validate_integrity(request)?;
        self.validate_page_provenance(page.provenance)
            .map(|()| page)
    }

    pub fn read_asset(&mut self, request: &AssetRequest) -> Result<AssetPage> {
        request.validate()?;
        let page = self.transport.read_asset(request)?;
        page.validate_integrity(request)?;
        self.validate_page_provenance(page.provenance)
            .map(|()| page)
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    fn validate_page_provenance(&self, provenance: TransportProvenance) -> Result<()> {
        if provenance == self.definition.provenance
            && !provenance.connected()
            && !provenance.native()
            && !provenance.first_party()
        {
            Ok(())
        } else {
            Err(FreshserviceIncidentResultError::TamperedEvidence)
        }
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PageCursor {
    pub token_digest: Digest,
    pub scope_digest: Digest,
    pub record_digest: Digest,
    pub filter_digest: Digest,
    pub page_number: u16,
}

impl PageCursor {
    pub fn new(
        opaque_token: impl AsRef<str>,
        scope_digest: &Digest,
        record_digest: &Digest,
        filter_digest: &Digest,
        page_number: u16,
    ) -> Result<Self> {
        if opaque_token.as_ref().is_empty() || page_number == 0 || page_number > MAX_PAGES {
            return Err(FreshserviceIncidentResultError::InvalidRequest);
        }
        Ok(Self {
            token_digest: Digest::from_parts(
                "freshservice-page-token/v1",
                &[("token", opaque_token.as_ref().to_owned())],
            ),
            scope_digest: scope_digest.clone(),
            record_digest: record_digest.clone(),
            filter_digest: filter_digest.clone(),
            page_number,
        })
    }

    pub fn digest(&self) -> Digest {
        Digest::from_parts(
            "freshservice-page-cursor/v1",
            &[
                ("token", self.token_digest.as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("record", self.record_digest.as_str().to_owned()),
                ("filter", self.filter_digest.as_str().to_owned()),
                ("page", self.page_number.to_string()),
            ],
        )
    }

    pub(crate) fn validate_for(
        &self,
        scope_digest: &Digest,
        record_digest: &Digest,
        filter_digest: &Digest,
    ) -> Result<()> {
        self.token_digest.validate()?;
        self.scope_digest.validate()?;
        self.record_digest.validate()?;
        self.filter_digest.validate()?;
        if &self.scope_digest != scope_digest
            || &self.record_digest != record_digest
            || &self.filter_digest != filter_digest
            || self.page_number == 0
            || self.page_number > MAX_PAGES
        {
            return Err(FreshserviceIncidentResultError::PaginationDrift);
        }
        Ok(())
    }
}

impl fmt::Debug for PageCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PageCursor")
            .field("cursor_digest", &self.digest())
            .field("page_number", &self.page_number)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IncidentRequest {
    pub scope_digest: Digest,
    pub record_digest: Digest,
    pub filter_digest: Digest,
    pub page_size: u16,
    pub cursor: Option<PageCursor>,
}

impl IncidentRequest {
    pub fn for_scope(
        scope: &FreshserviceIncidentResultScope,
        page_size: u16,
        cursor: Option<PageCursor>,
    ) -> Result<Self> {
        Self::new(scope, scope.incident().digest(), page_size, cursor)
    }

    pub fn new(
        scope: &FreshserviceIncidentResultScope,
        record_digest: Digest,
        page_size: u16,
        cursor: Option<PageCursor>,
    ) -> Result<Self> {
        let request = Self {
            scope_digest: scope.digest(),
            record_digest,
            filter_digest: filter_digest(scope, "incident"),
            page_size,
            cursor,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "/api/v2/incidents/{}?page_size={}&scope={}",
            &self.record_digest.as_str()[..16],
            self.page_size,
            &self.scope_digest.as_str()[..16]
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        validate_request(
            &self.scope_digest,
            &self.record_digest,
            &self.filter_digest,
            self.page_size,
            self.cursor.as_ref(),
        )
    }

    fn expected_page(&self) -> u16 {
        self.cursor.as_ref().map_or(1, |cursor| cursor.page_number)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeRequest {
    pub scope_digest: Digest,
    pub record_digest: Digest,
    pub filter_digest: Digest,
    pub page_size: u16,
    pub cursor: Option<PageCursor>,
}

impl ChangeRequest {
    pub fn for_scope(
        scope: &FreshserviceIncidentResultScope,
        page_size: u16,
        cursor: Option<PageCursor>,
    ) -> Result<Self> {
        Self::new(scope, scope.change().digest(), page_size, cursor)
    }

    pub fn new(
        scope: &FreshserviceIncidentResultScope,
        record_digest: Digest,
        page_size: u16,
        cursor: Option<PageCursor>,
    ) -> Result<Self> {
        let request = Self {
            scope_digest: scope.digest(),
            record_digest,
            filter_digest: filter_digest(scope, "change"),
            page_size,
            cursor,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "/api/v2/changes/{}?page_size={}&scope={}",
            &self.record_digest.as_str()[..16],
            self.page_size,
            &self.scope_digest.as_str()[..16]
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        validate_request(
            &self.scope_digest,
            &self.record_digest,
            &self.filter_digest,
            self.page_size,
            self.cursor.as_ref(),
        )
    }

    fn expected_page(&self) -> u16 {
        self.cursor.as_ref().map_or(1, |cursor| cursor.page_number)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssetRequest {
    pub scope_digest: Digest,
    pub record_digest: Digest,
    pub filter_digest: Digest,
    pub page_size: u16,
    pub cursor: Option<PageCursor>,
}

impl AssetRequest {
    pub fn for_scope(
        scope: &FreshserviceIncidentResultScope,
        page_size: u16,
        cursor: Option<PageCursor>,
    ) -> Result<Self> {
        Self::new(scope, scope.asset().digest(), page_size, cursor)
    }

    pub fn new(
        scope: &FreshserviceIncidentResultScope,
        record_digest: Digest,
        page_size: u16,
        cursor: Option<PageCursor>,
    ) -> Result<Self> {
        let request = Self {
            scope_digest: scope.digest(),
            record_digest,
            filter_digest: filter_digest(scope, "asset"),
            page_size,
            cursor,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "/api/v2/assets/{}?page_size={}&scope={}",
            &self.record_digest.as_str()[..16],
            self.page_size,
            &self.scope_digest.as_str()[..16]
        )
    }

    pub(crate) fn validate(&self) -> Result<()> {
        validate_request(
            &self.scope_digest,
            &self.record_digest,
            &self.filter_digest,
            self.page_size,
            self.cursor.as_ref(),
        )
    }

    fn expected_page(&self) -> u16 {
        self.cursor.as_ref().map_or(1, |cursor| cursor.page_number)
    }
}

fn filter_digest(scope: &FreshserviceIncidentResultScope, kind: &str) -> Digest {
    Digest::from_parts(
        "freshservice-filter/v1",
        &[
            ("kind", kind.to_owned()),
            ("account", scope.account().digest().as_str().to_owned()),
            ("agent", scope.agent().digest().as_str().to_owned()),
            ("group", scope.group().digest().as_str().to_owned()),
        ],
    )
}

fn validate_request(
    scope_digest: &Digest,
    record_digest: &Digest,
    filter_digest: &Digest,
    page_size: u16,
    cursor: Option<&PageCursor>,
) -> Result<()> {
    scope_digest.validate()?;
    record_digest.validate()?;
    filter_digest.validate()?;
    if page_size == 0 || page_size > MAX_PAGE_SIZE {
        return Err(FreshserviceIncidentResultError::InvalidRequest);
    }
    if let Some(cursor) = cursor {
        cursor.validate_for(scope_digest, record_digest, filter_digest)?;
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IncidentPage {
    pub items: Vec<IncidentMetadata>,
    pub next_cursor: Option<PageCursor>,
    pub complete: bool,
    pub page_number: u16,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
}

impl IncidentPage {
    pub fn new(
        request: &IncidentRequest,
        items: Vec<IncidentMetadata>,
        next_cursor: Option<PageCursor>,
        complete: bool,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        let page = Self {
            items,
            next_cursor,
            complete,
            page_number: request.expected_page(),
            response_bytes,
            provenance,
            response_digest: Digest::from_text("unsealed-freshservice-incident-page"),
        };
        page.validate_shape(request)?;
        Ok(Self {
            response_digest: page.calculate_digest(),
            ..page
        })
    }

    pub(crate) fn validate_integrity(&self, request: &IncidentRequest) -> Result<()> {
        self.validate_shape(request)?;
        if self.response_digest != self.calculate_digest() {
            return Err(FreshserviceIncidentResultError::TamperedEvidence);
        }
        Ok(())
    }

    fn validate_shape(&self, request: &IncidentRequest) -> Result<()> {
        request.validate()?;
        if self.page_number != request.expected_page()
            || self.items.len() > MAX_RECORDS_PER_KIND
            || self.response_bytes > MAX_RESPONSE_BYTES
            || (!self.complete && self.next_cursor.is_none())
            || (self.complete && self.next_cursor.is_some())
        {
            return Err(FreshserviceIncidentResultError::MalformedResponse);
        }
        if let Some(cursor) = &self.next_cursor {
            cursor.validate_for(
                &request.scope_digest,
                &request.record_digest,
                &request.filter_digest,
            )?;
            if cursor.page_number != self.page_number + 1 || cursor.page_number > MAX_PAGES {
                return Err(FreshserviceIncidentResultError::PaginationBoundExceeded);
            }
        }
        for item in &self.items {
            item.validate()?;
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "freshservice-incident-page/v1",
            &[
                (
                    "items",
                    serde_json::to_string(&self.items).expect("incident metadata serializes"),
                ),
                (
                    "next_cursor",
                    self.next_cursor
                        .as_ref()
                        .map_or_else(String::new, |cursor| cursor.digest().as_str().to_owned()),
                ),
                ("complete", self.complete.to_string()),
                ("page", self.page_number.to_string()),
                ("bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangePage {
    pub items: Vec<ChangeMetadata>,
    pub next_cursor: Option<PageCursor>,
    pub complete: bool,
    pub page_number: u16,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
}

impl ChangePage {
    pub fn new(
        request: &ChangeRequest,
        items: Vec<ChangeMetadata>,
        next_cursor: Option<PageCursor>,
        complete: bool,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        let page = Self {
            items,
            next_cursor,
            complete,
            page_number: request.expected_page(),
            response_bytes,
            provenance,
            response_digest: Digest::from_text("unsealed-freshservice-change-page"),
        };
        page.validate_shape(request)?;
        Ok(Self {
            response_digest: page.calculate_digest(),
            ..page
        })
    }

    pub(crate) fn validate_integrity(&self, request: &ChangeRequest) -> Result<()> {
        self.validate_shape(request)?;
        if self.response_digest != self.calculate_digest() {
            return Err(FreshserviceIncidentResultError::TamperedEvidence);
        }
        Ok(())
    }

    fn validate_shape(&self, request: &ChangeRequest) -> Result<()> {
        request.validate()?;
        if self.page_number != request.expected_page()
            || self.items.len() > MAX_RECORDS_PER_KIND
            || self.response_bytes > MAX_RESPONSE_BYTES
            || (!self.complete && self.next_cursor.is_none())
            || (self.complete && self.next_cursor.is_some())
        {
            return Err(FreshserviceIncidentResultError::MalformedResponse);
        }
        if let Some(cursor) = &self.next_cursor {
            cursor.validate_for(
                &request.scope_digest,
                &request.record_digest,
                &request.filter_digest,
            )?;
            if cursor.page_number != self.page_number + 1 || cursor.page_number > MAX_PAGES {
                return Err(FreshserviceIncidentResultError::PaginationBoundExceeded);
            }
        }
        for item in &self.items {
            item.validate()?;
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "freshservice-change-page/v1",
            &[
                (
                    "items",
                    serde_json::to_string(&self.items).expect("change metadata serializes"),
                ),
                (
                    "next_cursor",
                    self.next_cursor
                        .as_ref()
                        .map_or_else(String::new, |cursor| cursor.digest().as_str().to_owned()),
                ),
                ("complete", self.complete.to_string()),
                ("page", self.page_number.to_string()),
                ("bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssetPage {
    pub items: Vec<AssetMetadata>,
    pub next_cursor: Option<PageCursor>,
    pub complete: bool,
    pub page_number: u16,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub response_digest: Digest,
}

impl AssetPage {
    pub fn new(
        request: &AssetRequest,
        items: Vec<AssetMetadata>,
        next_cursor: Option<PageCursor>,
        complete: bool,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        let page = Self {
            items,
            next_cursor,
            complete,
            page_number: request.expected_page(),
            response_bytes,
            provenance,
            response_digest: Digest::from_text("unsealed-freshservice-asset-page"),
        };
        page.validate_shape(request)?;
        Ok(Self {
            response_digest: page.calculate_digest(),
            ..page
        })
    }

    pub(crate) fn validate_integrity(&self, request: &AssetRequest) -> Result<()> {
        self.validate_shape(request)?;
        if self.response_digest != self.calculate_digest() {
            return Err(FreshserviceIncidentResultError::TamperedEvidence);
        }
        Ok(())
    }

    fn validate_shape(&self, request: &AssetRequest) -> Result<()> {
        request.validate()?;
        if self.page_number != request.expected_page()
            || self.items.len() > MAX_RECORDS_PER_KIND
            || self.response_bytes > MAX_RESPONSE_BYTES
            || (!self.complete && self.next_cursor.is_none())
            || (self.complete && self.next_cursor.is_some())
        {
            return Err(FreshserviceIncidentResultError::MalformedResponse);
        }
        if let Some(cursor) = &self.next_cursor {
            cursor.validate_for(
                &request.scope_digest,
                &request.record_digest,
                &request.filter_digest,
            )?;
            if cursor.page_number != self.page_number + 1 || cursor.page_number > MAX_PAGES {
                return Err(FreshserviceIncidentResultError::PaginationBoundExceeded);
            }
        }
        for item in &self.items {
            item.validate()?;
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "freshservice-asset-page/v1",
            &[
                (
                    "items",
                    serde_json::to_string(&self.items).expect("asset metadata serializes"),
                ),
                (
                    "next_cursor",
                    self.next_cursor
                        .as_ref()
                        .map_or_else(String::new, |cursor| cursor.digest().as_str().to_owned()),
                ),
                ("complete", self.complete.to_string()),
                ("page", self.page_number.to_string()),
                ("bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "kind", content = "request")]
pub enum RecordedRequest {
    Incident(IncidentRequest),
    Change(ChangeRequest),
    Asset(AssetRequest),
}

#[derive(Default)]
pub struct RecordingTransport {
    incident_responses: VecDeque<Result<IncidentPage>>,
    change_responses: VecDeque<Result<ChangePage>>,
    asset_responses: VecDeque<Result<AssetPage>>,
    requests: Vec<RecordedRequest>,
}

impl fmt::Debug for RecordingTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordingTransport")
            .field("queued_incidents", &self.incident_responses.len())
            .field("queued_changes", &self.change_responses.len())
            .field("queued_assets", &self.asset_responses.len())
            .field("request_count", &self.requests.len())
            .finish()
    }
}

impl RecordingTransport {
    pub fn push_incident_response(&mut self, response: Result<IncidentPage>) {
        self.incident_responses.push_back(response);
    }

    pub fn push_change_response(&mut self, response: Result<ChangePage>) {
        self.change_responses.push_back(response);
    }

    pub fn push_asset_response(&mut self, response: Result<AssetPage>) {
        self.asset_responses.push_back(response);
    }

    pub fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }
}

impl FreshserviceTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn read_incident(&mut self, request: &IncidentRequest) -> Result<IncidentPage> {
        self.requests
            .push(RecordedRequest::Incident(request.clone()));
        self.incident_responses.pop_front().unwrap_or(Err(
            FreshserviceIncidentResultError::Provider(FreshserviceTransportError::BlockedEnv),
        ))
    }

    fn read_change(&mut self, request: &ChangeRequest) -> Result<ChangePage> {
        self.requests.push(RecordedRequest::Change(request.clone()));
        self.change_responses
            .pop_front()
            .unwrap_or(Err(FreshserviceIncidentResultError::Provider(
                FreshserviceTransportError::BlockedEnv,
            )))
    }

    fn read_asset(&mut self, request: &AssetRequest) -> Result<AssetPage> {
        self.requests.push(RecordedRequest::Asset(request.clone()));
        self.asset_responses
            .pop_front()
            .unwrap_or(Err(FreshserviceIncidentResultError::Provider(
                FreshserviceTransportError::BlockedEnv,
            )))
    }
}

#[derive(Clone)]
pub struct FixtureTransport {
    scope: FreshserviceIncidentResultScope,
    observed_at: DateTime<Utc>,
}

impl fmt::Debug for FixtureTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FixtureTransport")
            .field("scope_digest", &self.scope.digest())
            .field("observed_at", &self.observed_at)
            .finish()
    }
}

impl FixtureTransport {
    pub fn for_scope(scope: &FreshserviceIncidentResultScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            scope: scope.clone(),
            observed_at,
        }
    }

    fn incident_page(&self, request: &IncidentRequest) -> Result<IncidentPage> {
        let item = IncidentMetadata::new(
            &self.scope,
            IncidentStatus::Open,
            IncidentPriority::High,
            self.observed_at,
            3,
        )?;
        IncidentPage::new(request, vec![item], None, true, 512, self.provenance())
    }

    fn change_page(&self, request: &ChangeRequest) -> Result<ChangePage> {
        let window = ChangeWindowMetadata::new(
            Some(self.observed_at + Duration::hours(2)),
            Some(self.observed_at + Duration::hours(4)),
            None,
            None,
        )?;
        let item = ChangeMetadata::new(
            &self.scope,
            ChangeStatus::Planned,
            ChangeRisk::Medium,
            window,
            self.observed_at,
            2,
        )?;
        ChangePage::new(request, vec![item], None, true, 512, self.provenance())
    }

    fn asset_page(&self, request: &AssetRequest) -> Result<AssetPage> {
        let item = AssetMetadata::new(
            &self.scope,
            AssetLifecycle::Active,
            Some("server"),
            self.observed_at,
            5,
        )?;
        AssetPage::new(request, vec![item], None, true, 512, self.provenance())
    }
}

impl FreshserviceTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn read_incident(&mut self, request: &IncidentRequest) -> Result<IncidentPage> {
        self.incident_page(request)
    }

    fn read_change(&mut self, request: &ChangeRequest) -> Result<ChangePage> {
        self.change_page(request)
    }

    fn read_asset(&mut self, request: &AssetRequest) -> Result<AssetPage> {
        self.asset_page(request)
    }
}

#[derive(Clone)]
pub struct FakeTransport {
    fixture: FixtureTransport,
}

impl fmt::Debug for FakeTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FakeTransport")
            .field("scope_digest", &self.fixture.scope.digest())
            .field("observed_at", &self.fixture.observed_at)
            .finish()
    }
}

impl FakeTransport {
    pub fn for_scope(scope: &FreshserviceIncidentResultScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            fixture: FixtureTransport {
                scope: scope.clone(),
                observed_at,
            },
        }
    }
}

impl FreshserviceTransport for FakeTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fake
    }

    fn read_incident(&mut self, request: &IncidentRequest) -> Result<IncidentPage> {
        let item = IncidentMetadata::new(
            &self.fixture.scope,
            IncidentStatus::Pending,
            IncidentPriority::Medium,
            self.fixture.observed_at,
            4,
        )?;
        IncidentPage::new(request, vec![item], None, true, 512, self.provenance())
    }

    fn read_change(&mut self, request: &ChangeRequest) -> Result<ChangePage> {
        let window = ChangeWindowMetadata::new(None, None, None, None)?;
        let item = ChangeMetadata::new(
            &self.fixture.scope,
            ChangeStatus::Open,
            ChangeRisk::Low,
            window,
            self.fixture.observed_at,
            4,
        )?;
        ChangePage::new(request, vec![item], None, true, 512, self.provenance())
    }

    fn read_asset(&mut self, request: &AssetRequest) -> Result<AssetPage> {
        let item = AssetMetadata::new(
            &self.fixture.scope,
            AssetLifecycle::InStock,
            Some("workstation"),
            self.fixture.observed_at,
            4,
        )?;
        AssetPage::new(request, vec![item], None, true, 512, self.provenance())
    }
}

#[derive(Clone)]
pub struct LoopbackTransport {
    fixture: FixtureTransport,
}

impl fmt::Debug for LoopbackTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoopbackTransport")
            .field("scope_digest", &self.fixture.scope.digest())
            .field("observed_at", &self.fixture.observed_at)
            .finish()
    }
}

impl LoopbackTransport {
    pub fn for_scope(scope: &FreshserviceIncidentResultScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            fixture: FixtureTransport {
                scope: scope.clone(),
                observed_at,
            },
        }
    }
}

impl FreshserviceTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn read_incident(&mut self, request: &IncidentRequest) -> Result<IncidentPage> {
        self.fixture.incident_page(request).and_then(|page| {
            IncidentPage::new(
                request,
                page.items,
                page.next_cursor,
                page.complete,
                page.response_bytes,
                self.provenance(),
            )
        })
    }

    fn read_change(&mut self, request: &ChangeRequest) -> Result<ChangePage> {
        self.fixture.change_page(request).and_then(|page| {
            ChangePage::new(
                request,
                page.items,
                page.next_cursor,
                page.complete,
                page.response_bytes,
                self.provenance(),
            )
        })
    }

    fn read_asset(&mut self, request: &AssetRequest) -> Result<AssetPage> {
        self.fixture.asset_page(request).and_then(|page| {
            AssetPage::new(
                request,
                page.items,
                page.next_cursor,
                page.complete,
                page.response_bytes,
                self.provenance(),
            )
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvTransport;

impl FreshserviceTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn read_incident(&mut self, _request: &IncidentRequest) -> Result<IncidentPage> {
        Err(FreshserviceIncidentResultError::Provider(
            FreshserviceTransportError::BlockedEnv,
        ))
    }

    fn read_change(&mut self, _request: &ChangeRequest) -> Result<ChangePage> {
        Err(FreshserviceIncidentResultError::Provider(
            FreshserviceTransportError::BlockedEnv,
        ))
    }

    fn read_asset(&mut self, _request: &AssetRequest) -> Result<AssetPage> {
        Err(FreshserviceIncidentResultError::Provider(
            FreshserviceTransportError::BlockedEnv,
        ))
    }
}
