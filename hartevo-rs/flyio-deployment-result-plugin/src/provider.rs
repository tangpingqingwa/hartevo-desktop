use std::{collections::VecDeque, fmt};

use serde::Serialize;

use crate::error::{FlyioDeploymentResultError, FlyioTransportError, Result};
use crate::model::{
    AppEvidence, Digest, FlyioDeploymentScope, MachineEvidence, TransportProvenance,
};
use crate::{
    API_REVISION, CONTRACT_VERSION, MAX_MACHINE_CARDINALITY, MAX_PAGE_SIZE, MAX_PAGES,
    MAX_RESPONSE_BYTES, PROVIDER_ID,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum FlyioOperation {
    ListApps,
    GetApp,
    ListMachines,
    GetMachine,
}

impl FlyioOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ListApps => "ListApps",
            Self::GetApp => "GetApp",
            Self::ListMachines => "ListMachines",
            Self::GetMachine => "GetMachine",
        }
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct Cursor {
    marker_digest: Digest,
    scope_digest: Digest,
    page_number: u16,
}

impl Cursor {
    pub fn new(
        opaque_marker: impl Into<String>,
        scope: &FlyioDeploymentScope,
        page_number: u16,
    ) -> Result<Self> {
        let marker = opaque_marker.into();
        if marker.is_empty() || marker.len() > crate::MAX_IDENTIFIER_BYTES || page_number < 2 {
            return Err(FlyioDeploymentResultError::InvalidRequest);
        }
        if page_number > MAX_PAGES {
            return Err(FlyioDeploymentResultError::PartialEvidence);
        }
        let cursor = Self {
            marker_digest: Digest::from_parts(
                "flyio-opaque-cursor/v1",
                &[
                    ("marker", marker),
                    ("scope", scope.digest().as_str().to_owned()),
                ],
            ),
            scope_digest: scope.digest(),
            page_number,
        };
        cursor.validate(scope)?;
        Ok(cursor)
    }

    pub fn marker_digest(&self) -> &Digest {
        &self.marker_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    fn validate(&self, scope: &FlyioDeploymentScope) -> Result<()> {
        if self.page_number < 2 || self.page_number > MAX_PAGES {
            return Err(FlyioDeploymentResultError::InvalidRequest);
        }
        if self.scope_digest != scope.digest() {
            return Err(FlyioDeploymentResultError::ScopeMismatch);
        }
        self.marker_digest.validate()
    }
}

impl fmt::Debug for Cursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Cursor")
            .field("marker_digest", &self.marker_digest)
            .field("scope_digest", &self.scope_digest)
            .field("page_number", &self.page_number)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: FlyioOperation,
    pub scope_digest: Digest,
    pub app_digest: Digest,
    pub machine_digest: Digest,
    pub cursor_digest: Option<Digest>,
    pub request_digest: Digest,
    pub path_digest: Digest,
    pub response_bytes: u64,
    pub redacted: bool,
}

#[derive(Clone, Eq, PartialEq)]
pub struct ListAppsRequest {
    scope: FlyioDeploymentScope,
    page_size: u16,
    page_number: u16,
    cursor: Option<Cursor>,
    request_digest: Digest,
}

impl ListAppsRequest {
    pub fn new(
        scope: &FlyioDeploymentScope,
        page_size: u16,
        cursor: Option<Cursor>,
    ) -> Result<Self> {
        scope.validate()?;
        validate_page_size(page_size)?;
        if let Some(cursor) = cursor.as_ref() {
            cursor.validate(scope)?;
        }
        let page_number = cursor.as_ref().map_or(1, Cursor::page_number);
        let request_digest = Digest::from_parts(
            "flyio-list-apps-request/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("page_size", page_size.to_string()),
                ("page_number", page_number.to_string()),
                (
                    "cursor",
                    cursor.as_ref().map_or_else(String::new, |value| {
                        value.marker_digest().as_str().to_owned()
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

    pub fn first(scope: &FlyioDeploymentScope, page_size: u16) -> Result<Self> {
        Self::new(scope, page_size, None)
    }

    pub fn scope(&self) -> &FlyioDeploymentScope {
        &self.scope
    }

    pub const fn page_size(&self) -> u16 {
        self.page_size
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub fn cursor(&self) -> Option<&Cursor> {
        self.cursor.as_ref()
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "/v1/apps?org_slug={}&page={}&per_page={}",
            &self.scope.organization().digest().as_str()[..16],
            self.page_number,
            self.page_size
        )
    }

    pub fn recorded_request(&self, response_bytes: u64) -> RecordedRequest {
        RecordedRequest {
            operation: FlyioOperation::ListApps,
            scope_digest: self.scope.digest(),
            app_digest: self.scope.app().digest(),
            machine_digest: self.scope.machine_id().digest(),
            cursor_digest: self
                .cursor
                .as_ref()
                .map(|cursor| cursor.marker_digest().clone()),
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
            response_bytes,
            redacted: true,
        }
    }
}

impl fmt::Debug for ListAppsRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListAppsRequest")
            .field("scope_digest", &self.scope.digest())
            .field("page_size", &self.page_size)
            .field("page_number", &self.page_number)
            .field("cursor", &self.cursor)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GetAppRequest {
    scope: FlyioDeploymentScope,
    request_digest: Digest,
}

impl GetAppRequest {
    pub fn for_scope(scope: &FlyioDeploymentScope) -> Result<Self> {
        scope.validate()?;
        Ok(Self {
            scope: scope.clone(),
            request_digest: Digest::from_parts(
                "flyio-get-app-request/v1",
                &[
                    ("scope", scope.digest().as_str().to_owned()),
                    ("app", scope.app().digest().as_str().to_owned()),
                ],
            ),
        })
    }

    pub fn scope(&self) -> &FlyioDeploymentScope {
        &self.scope
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "/v1/apps/{}",
            &self.scope.app().name().digest().as_str()[..16]
        )
    }

    pub fn recorded_request(&self, response_bytes: u64) -> RecordedRequest {
        RecordedRequest {
            operation: FlyioOperation::GetApp,
            scope_digest: self.scope.digest(),
            app_digest: self.scope.app().digest(),
            machine_digest: self.scope.machine_id().digest(),
            cursor_digest: None,
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
            response_bytes,
            redacted: true,
        }
    }
}

impl fmt::Debug for GetAppRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GetAppRequest")
            .field("scope_digest", &self.scope.digest())
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ListMachinesRequest {
    scope: FlyioDeploymentScope,
    page_size: u16,
    page_number: u16,
    cursor: Option<Cursor>,
    request_digest: Digest,
}

impl ListMachinesRequest {
    pub fn new(
        scope: &FlyioDeploymentScope,
        page_size: u16,
        cursor: Option<Cursor>,
    ) -> Result<Self> {
        scope.validate()?;
        validate_page_size(page_size)?;
        if let Some(cursor) = cursor.as_ref() {
            cursor.validate(scope)?;
        }
        let page_number = cursor.as_ref().map_or(1, Cursor::page_number);
        let request_digest = Digest::from_parts(
            "flyio-list-machines-request/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("app", scope.app().digest().as_str().to_owned()),
                ("region", scope.region().digest().as_str().to_owned()),
                (
                    "process_group",
                    scope.process_group().digest().as_str().to_owned(),
                ),
                ("page_size", page_size.to_string()),
                ("page_number", page_number.to_string()),
                (
                    "cursor",
                    cursor.as_ref().map_or_else(String::new, |value| {
                        value.marker_digest().as_str().to_owned()
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

    pub fn first(scope: &FlyioDeploymentScope, page_size: u16) -> Result<Self> {
        Self::new(scope, page_size, None)
    }

    pub fn scope(&self) -> &FlyioDeploymentScope {
        &self.scope
    }

    pub const fn page_size(&self) -> u16 {
        self.page_size
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub fn cursor(&self) -> Option<&Cursor> {
        self.cursor.as_ref()
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "/v1/apps/{}/machines?region={}&page={}&per_page={}",
            &self.scope.app().name().digest().as_str()[..16],
            &self.scope.region().digest().as_str()[..16],
            self.page_number,
            self.page_size
        )
    }

    pub fn recorded_request(&self, response_bytes: u64) -> RecordedRequest {
        RecordedRequest {
            operation: FlyioOperation::ListMachines,
            scope_digest: self.scope.digest(),
            app_digest: self.scope.app().digest(),
            machine_digest: self.scope.machine_id().digest(),
            cursor_digest: self
                .cursor
                .as_ref()
                .map(|cursor| cursor.marker_digest().clone()),
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
            response_bytes,
            redacted: true,
        }
    }
}

impl fmt::Debug for ListMachinesRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListMachinesRequest")
            .field("scope_digest", &self.scope.digest())
            .field("page_size", &self.page_size)
            .field("page_number", &self.page_number)
            .field("cursor", &self.cursor)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GetMachineRequest {
    scope: FlyioDeploymentScope,
    request_digest: Digest,
}

impl GetMachineRequest {
    pub fn for_scope(scope: &FlyioDeploymentScope) -> Result<Self> {
        scope.validate()?;
        Ok(Self {
            scope: scope.clone(),
            request_digest: Digest::from_parts(
                "flyio-get-machine-request/v1",
                &[
                    ("scope", scope.digest().as_str().to_owned()),
                    ("app", scope.app().digest().as_str().to_owned()),
                    ("machine", scope.machine_id().digest().as_str().to_owned()),
                    ("instance", scope.instance_id().digest().as_str().to_owned()),
                ],
            ),
        })
    }

    pub fn scope(&self) -> &FlyioDeploymentScope {
        &self.scope
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "/v1/apps/{}/machines/{}",
            &self.scope.app().name().digest().as_str()[..16],
            &self.scope.machine_id().digest().as_str()[..16]
        )
    }

    pub fn recorded_request(&self, response_bytes: u64) -> RecordedRequest {
        RecordedRequest {
            operation: FlyioOperation::GetMachine,
            scope_digest: self.scope.digest(),
            app_digest: self.scope.app().digest(),
            machine_digest: self.scope.machine_id().digest(),
            cursor_digest: None,
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query()),
            response_bytes,
            redacted: true,
        }
    }
}

impl fmt::Debug for GetMachineRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GetMachineRequest")
            .field("scope_digest", &self.scope.digest())
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppPage {
    pub apps: Vec<AppEvidence>,
    pub next_cursor: Option<Cursor>,
    pub response_bytes: u64,
    pub response_digest: Digest,
    pub truncated: bool,
}

impl AppPage {
    pub fn new(
        apps: Vec<AppEvidence>,
        next_cursor: Option<Cursor>,
        response_bytes: u64,
        response_digest: Digest,
        truncated: bool,
    ) -> Result<Self> {
        let page = Self {
            apps,
            next_cursor,
            response_bytes,
            response_digest,
            truncated,
        };
        page.validate_bound(response_bytes <= MAX_RESPONSE_BYTES)?;
        Ok(page)
    }

    fn validate_bound(&self, response_size_ok: bool) -> Result<()> {
        if !response_size_ok
            || self.apps.len() > MAX_MACHINE_CARDINALITY
            || self.response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(FlyioDeploymentResultError::PartialEvidence);
        }
        self.response_digest.validate()?;
        Ok(())
    }

    fn validate(&self, scope: &FlyioDeploymentScope) -> Result<()> {
        self.validate_bound(true)?;
        if let Some(cursor) = self.next_cursor.as_ref() {
            cursor.validate(scope)?;
        }
        for app in &self.apps {
            app.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MachinePage {
    pub machines: Vec<MachineEvidence>,
    pub next_cursor: Option<Cursor>,
    pub response_bytes: u64,
    pub response_digest: Digest,
    pub truncated: bool,
}

impl MachinePage {
    pub fn new(
        machines: Vec<MachineEvidence>,
        next_cursor: Option<Cursor>,
        response_bytes: u64,
        response_digest: Digest,
        truncated: bool,
    ) -> Result<Self> {
        let page = Self {
            machines,
            next_cursor,
            response_bytes,
            response_digest,
            truncated,
        };
        page.validate_bound(response_bytes <= MAX_RESPONSE_BYTES)?;
        Ok(page)
    }

    fn validate_bound(&self, response_size_ok: bool) -> Result<()> {
        if !response_size_ok
            || self.machines.len() > MAX_MACHINE_CARDINALITY
            || self.response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(FlyioDeploymentResultError::PartialEvidence);
        }
        self.response_digest.validate()?;
        Ok(())
    }

    fn validate(&self, scope: &FlyioDeploymentScope) -> Result<()> {
        self.validate_bound(true)?;
        if let Some(cursor) = self.next_cursor.as_ref() {
            cursor.validate(scope)?;
        }
        for machine in &self.machines {
            machine.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportResponse<T> {
    pub value: T,
    pub response_bytes: u64,
    pub response_digest: Digest,
    pub truncated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FixtureResponse {
    Apps(std::result::Result<AppPage, FlyioTransportError>),
    App(std::result::Result<AppPage, FlyioTransportError>),
    Machines(std::result::Result<MachinePage, FlyioTransportError>),
    Machine(std::result::Result<MachinePage, FlyioTransportError>),
}

pub trait FlyioTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn list_apps(
        &mut self,
        request: &ListAppsRequest,
    ) -> std::result::Result<AppPage, FlyioTransportError>;

    fn get_app(
        &mut self,
        request: &GetAppRequest,
    ) -> std::result::Result<AppPage, FlyioTransportError>;

    fn list_machines(
        &mut self,
        request: &ListMachinesRequest,
    ) -> std::result::Result<MachinePage, FlyioTransportError>;

    fn get_machine(
        &mut self,
        request: &GetMachineRequest,
    ) -> std::result::Result<MachinePage, FlyioTransportError>;
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    responses: VecDeque<FixtureResponse>,
}

impl FixtureTransport {
    pub fn new(responses: impl IntoIterator<Item = FixtureResponse>) -> Self {
        Self {
            responses: responses.into_iter().collect(),
        }
    }

    pub fn fixture(responses: impl IntoIterator<Item = FixtureResponse>) -> Self {
        Self::new(responses)
    }

    fn next_apps(&mut self) -> std::result::Result<AppPage, FlyioTransportError> {
        match self.responses.pop_front() {
            Some(FixtureResponse::Apps(response) | FixtureResponse::App(response)) => response,
            Some(_) | None => Err(FlyioTransportError::InvalidResponse),
        }
    }

    fn next_machines(&mut self) -> std::result::Result<MachinePage, FlyioTransportError> {
        match self.responses.pop_front() {
            Some(FixtureResponse::Machines(response) | FixtureResponse::Machine(response)) => {
                response
            }
            Some(_) | None => Err(FlyioTransportError::InvalidResponse),
        }
    }
}

impl FlyioTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn list_apps(
        &mut self,
        _request: &ListAppsRequest,
    ) -> std::result::Result<AppPage, FlyioTransportError> {
        self.next_apps()
    }

    fn get_app(
        &mut self,
        _request: &GetAppRequest,
    ) -> std::result::Result<AppPage, FlyioTransportError> {
        self.next_apps()
    }

    fn list_machines(
        &mut self,
        _request: &ListMachinesRequest,
    ) -> std::result::Result<MachinePage, FlyioTransportError> {
        self.next_machines()
    }

    fn get_machine(
        &mut self,
        _request: &GetMachineRequest,
    ) -> std::result::Result<MachinePage, FlyioTransportError> {
        self.next_machines()
    }
}

#[derive(Clone, Debug)]
pub struct RecordingTransport {
    fixture: FixtureTransport,
    requests: Vec<RecordedRequest>,
}

impl RecordingTransport {
    pub fn new(responses: impl IntoIterator<Item = FixtureResponse>) -> Self {
        Self {
            fixture: FixtureTransport::new(responses),
            requests: Vec::new(),
        }
    }

    pub fn fixture(responses: impl IntoIterator<Item = FixtureResponse>) -> Self {
        Self::new(responses)
    }

    pub fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }
}

impl FlyioTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Recording
    }

    fn list_apps(
        &mut self,
        request: &ListAppsRequest,
    ) -> std::result::Result<AppPage, FlyioTransportError> {
        let response = self.fixture.list_apps(request)?;
        self.requests
            .push(request.recorded_request(response.response_bytes));
        Ok(response)
    }

    fn get_app(
        &mut self,
        request: &GetAppRequest,
    ) -> std::result::Result<AppPage, FlyioTransportError> {
        let response = self.fixture.get_app(request)?;
        self.requests
            .push(request.recorded_request(response.response_bytes));
        Ok(response)
    }

    fn list_machines(
        &mut self,
        request: &ListMachinesRequest,
    ) -> std::result::Result<MachinePage, FlyioTransportError> {
        let response = self.fixture.list_machines(request)?;
        self.requests
            .push(request.recorded_request(response.response_bytes));
        Ok(response)
    }

    fn get_machine(
        &mut self,
        request: &GetMachineRequest,
    ) -> std::result::Result<MachinePage, FlyioTransportError> {
        let response = self.fixture.get_machine(request)?;
        self.requests
            .push(request.recorded_request(response.response_bytes));
        Ok(response)
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    fixture: FixtureTransport,
}

impl LoopbackTransport {
    pub fn new(responses: impl IntoIterator<Item = FixtureResponse>) -> Self {
        Self {
            fixture: FixtureTransport::new(responses),
        }
    }

    pub fn fixture(responses: impl IntoIterator<Item = FixtureResponse>) -> Self {
        Self::new(responses)
    }
}

impl FlyioTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn list_apps(
        &mut self,
        request: &ListAppsRequest,
    ) -> std::result::Result<AppPage, FlyioTransportError> {
        self.fixture.list_apps(request)
    }

    fn get_app(
        &mut self,
        request: &GetAppRequest,
    ) -> std::result::Result<AppPage, FlyioTransportError> {
        self.fixture.get_app(request)
    }

    fn list_machines(
        &mut self,
        request: &ListMachinesRequest,
    ) -> std::result::Result<MachinePage, FlyioTransportError> {
        self.fixture.list_machines(request)
    }

    fn get_machine(
        &mut self,
        request: &GetMachineRequest,
    ) -> std::result::Result<MachinePage, FlyioTransportError> {
        self.fixture.get_machine(request)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlockedEnvTransport;

impl FlyioTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn list_apps(
        &mut self,
        _request: &ListAppsRequest,
    ) -> std::result::Result<AppPage, FlyioTransportError> {
        Err(FlyioTransportError::BlockedEnv)
    }

    fn get_app(
        &mut self,
        _request: &GetAppRequest,
    ) -> std::result::Result<AppPage, FlyioTransportError> {
        Err(FlyioTransportError::BlockedEnv)
    }

    fn list_machines(
        &mut self,
        _request: &ListMachinesRequest,
    ) -> std::result::Result<MachinePage, FlyioTransportError> {
        Err(FlyioTransportError::BlockedEnv)
    }

    fn get_machine(
        &mut self,
        _request: &GetMachineRequest,
    ) -> std::result::Result<MachinePage, FlyioTransportError> {
        Err(FlyioTransportError::BlockedEnv)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FlyioMachinesProviderDefinition {
    pub provider_id: String,
    pub provider_revision: u64,
    pub release: String,
    pub api_revision: String,
    pub provider_digest: Digest,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub external_writes: bool,
}

impl FlyioMachinesProviderDefinition {
    pub fn for_provenance(provenance: TransportProvenance) -> Result<Self> {
        let mut definition = Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_revision: 1,
            release: "flyio-layer1-recording-r1".to_owned(),
            api_revision: API_REVISION.to_owned(),
            provider_digest: Digest::from_text("unsealed-flyio-provider"),
            provenance,
            connected: false,
            native: false,
            first_party: false,
            external_writes: false,
        };
        definition.provider_digest = definition.calculate_digest();
        definition.validate()?;
        Ok(definition)
    }

    pub fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "flyio-provider-definition/v1",
            &[
                ("id", self.provider_id.clone()),
                ("revision", self.provider_revision.to_string()),
                ("release", self.release.clone()),
                ("api", self.api_revision.clone()),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }

    pub fn validate(&self) -> Result<()> {
        if self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.release.is_empty()
            || self.api_revision != API_REVISION
            || self.connected
            || self.native
            || self.first_party
            || self.external_writes
            || self.provider_digest != self.calculate_digest()
        {
            return Err(FlyioDeploymentResultError::ProviderDrift);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct FlyioMachinesProvider<T: FlyioTransport> {
    scope: FlyioDeploymentScope,
    transport: T,
    definition: FlyioMachinesProviderDefinition,
}

impl<T: FlyioTransport> FlyioMachinesProvider<T> {
    pub fn new(scope: FlyioDeploymentScope, transport: T) -> Result<Self> {
        scope.validate()?;
        let definition = FlyioMachinesProviderDefinition::for_provenance(transport.provenance())?;
        Ok(Self {
            scope,
            transport,
            definition,
        })
    }

    pub fn scope(&self) -> &FlyioDeploymentScope {
        &self.scope
    }

    pub fn definition(&self) -> &FlyioMachinesProviderDefinition {
        &self.definition
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub const fn connected(&self) -> bool {
        false
    }

    pub const fn native(&self) -> bool {
        false
    }

    pub const fn first_party(&self) -> bool {
        false
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn list_apps(&mut self, request: &ListAppsRequest) -> Result<AppPage> {
        self.ensure_scope(request.scope())?;
        let page = self
            .transport
            .list_apps(request)
            .map_err(FlyioDeploymentResultError::Transport)?;
        page.validate(&self.scope)?;
        Ok(page)
    }

    pub fn get_app(&mut self, request: &GetAppRequest) -> Result<AppPage> {
        self.ensure_scope(request.scope())?;
        let page = self
            .transport
            .get_app(request)
            .map_err(FlyioDeploymentResultError::Transport)?;
        page.validate(&self.scope)?;
        Ok(page)
    }

    pub fn list_machines(&mut self, request: &ListMachinesRequest) -> Result<MachinePage> {
        self.ensure_scope(request.scope())?;
        let page = self
            .transport
            .list_machines(request)
            .map_err(FlyioDeploymentResultError::Transport)?;
        page.validate(&self.scope)?;
        Ok(page)
    }

    pub fn get_machine(&mut self, request: &GetMachineRequest) -> Result<MachinePage> {
        self.ensure_scope(request.scope())?;
        let page = self
            .transport
            .get_machine(request)
            .map_err(FlyioDeploymentResultError::Transport)?;
        page.validate(&self.scope)?;
        Ok(page)
    }

    fn ensure_scope(&self, request_scope: &FlyioDeploymentScope) -> Result<()> {
        if request_scope.digest() != self.scope.digest() {
            Err(FlyioDeploymentResultError::ScopeMismatch)
        } else {
            Ok(())
        }
    }
}

fn validate_page_size(page_size: u16) -> Result<()> {
    if page_size == 0 || page_size > MAX_PAGE_SIZE {
        Err(FlyioDeploymentResultError::InvalidRequest)
    } else {
        Ok(())
    }
}

#[allow(dead_code)]
fn _contract_version_marker() -> &'static str {
    CONTRACT_VERSION
}
