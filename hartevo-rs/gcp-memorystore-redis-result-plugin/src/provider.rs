use std::{collections::VecDeque, fmt};

use serde::Serialize;

use crate::error::{GcpMemorystoreError, GcpMemorystoreTransportError, Result};
use crate::model::{
    CostReceipt, Digest, GcpMemorystoreScope, InstanceInput, InstanceSummary, OpaquePageToken,
    RequestReceipt, TransportProvenance, optional_digest,
};
use crate::{
    API_REVISION, CONTRACT_VERSION, MAX_LIST_ITEMS, MAX_PAGE_SIZE, MAX_PAGES, MAX_RESPONSE_BYTES,
    PLUGIN_VERSION, PROVIDER_ID,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GcpMemorystoreOperation {
    InstancesList,
    InstancesGet,
}
impl GcpMemorystoreOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InstancesList => "instances.list",
            Self::InstancesGet => "instances.get",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: GcpMemorystoreOperation,
    pub request_digest: Digest,
    pub path_digest: Digest,
    pub scope_digest: Digest,
    pub project_digest: Digest,
    pub location_digest: Digest,
    pub instance_digest: Digest,
    pub page_token_digest: Option<Digest>,
    pub api_digest: Digest,
}
impl RecordedRequest {
    fn from_parts(
        operation: GcpMemorystoreOperation,
        request_digest: Digest,
        path_digest: Digest,
        scope: &GcpMemorystoreScope,
        page_token_digest: Option<Digest>,
    ) -> Self {
        Self {
            operation,
            request_digest,
            path_digest,
            scope_digest: scope.digest(),
            project_digest: scope.gcp_project().digest(),
            location_digest: scope.location().digest(),
            instance_digest: scope.instance().digest(),
            page_token_digest,
            api_digest: scope.api_digest(),
        }
    }
    pub(crate) fn receipt(&self) -> RequestReceipt {
        RequestReceipt {
            operation: self.operation.as_str().to_owned(),
            request_digest: self.request_digest.clone(),
            path_digest: self.path_digest.clone(),
            scope_digest: self.scope_digest.clone(),
            project_digest: self.project_digest.clone(),
            location_digest: self.location_digest.clone(),
            instance_digest: self.instance_digest.clone(),
            page_token_digest: self.page_token_digest.clone(),
            api_digest: self.api_digest.clone(),
        }
    }
    pub(crate) fn validate(&self) -> Result<()> {
        self.receipt().validate()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ListInstancesRequest {
    scope: GcpMemorystoreScope,
    page_size: u32,
    page_number: u16,
    page_token: Option<OpaquePageToken>,
    request_digest: Digest,
    recorded: RecordedRequest,
}
impl fmt::Debug for ListInstancesRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListInstancesRequest")
            .field("scope_digest", &self.scope.digest())
            .field("page_size", &self.page_size)
            .field("page_number", &self.page_number)
            .field(
                "page_token_digest",
                &self.page_token.as_ref().map(OpaquePageToken::digest),
            )
            .field("request_digest", &self.request_digest)
            .finish_non_exhaustive()
    }
}
impl ListInstancesRequest {
    pub fn new(
        scope: &GcpMemorystoreScope,
        page_size: u32,
        page_number: u16,
        page_token: Option<OpaquePageToken>,
    ) -> Result<Self> {
        scope.validate()?;
        if !(1..=MAX_PAGE_SIZE).contains(&page_size)
            || !(1..=MAX_PAGES).contains(&page_number)
            || page_token
                .as_ref()
                .is_some_and(|token| token.validate().is_err())
        {
            return Err(GcpMemorystoreError::InvalidRequest);
        }
        let token_digest = page_token.as_ref().map(OpaquePageToken::digest);
        let request_digest = Digest::from_parts(
            "gcp-memorystore-list-request/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("project", scope.gcp_project().digest().as_str().to_owned()),
                ("location", scope.location().digest().as_str().to_owned()),
                ("instance", scope.instance().digest().as_str().to_owned()),
                ("page_size", page_size.to_string()),
                ("page_number", page_number.to_string()),
                ("page_token", optional_digest(token_digest.as_ref())),
                ("api", scope.api_digest().as_str().to_owned()),
                ("permission", scope.permission_digest().as_str().to_owned()),
            ],
        );
        let path_digest = Digest::from_parts(
            "gcp-memorystore-list-path/v1",
            &[
                (
                    "parent",
                    Digest::from_parts(
                        "gcp-memorystore-parent/v1",
                        &[
                            ("project", scope.gcp_project().digest().as_str().to_owned()),
                            ("location", scope.location().digest().as_str().to_owned()),
                        ],
                    )
                    .as_str()
                    .to_owned(),
                ),
                ("api", API_REVISION.to_owned()),
            ],
        );
        let recorded = RecordedRequest::from_parts(
            GcpMemorystoreOperation::InstancesList,
            request_digest.clone(),
            path_digest,
            scope,
            token_digest,
        );
        Ok(Self {
            scope: scope.clone(),
            page_size,
            page_number,
            page_token,
            request_digest,
            recorded,
        })
    }
    pub fn first(scope: &GcpMemorystoreScope, page_size: u32) -> Result<Self> {
        Self::new(scope, page_size, 1, None)
    }
    pub fn scope(&self) -> &GcpMemorystoreScope {
        &self.scope
    }
    pub const fn page_size(&self) -> u32 {
        self.page_size
    }
    pub const fn page_number(&self) -> u16 {
        self.page_number
    }
    pub fn page_token(&self) -> Option<&OpaquePageToken> {
        self.page_token.as_ref()
    }
    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }
    pub fn recorded_request(&self) -> RecordedRequest {
        self.recorded.clone()
    }
    pub(crate) fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        self.recorded.validate()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GetInstanceRequest {
    scope: GcpMemorystoreScope,
    request_digest: Digest,
    recorded: RecordedRequest,
}
impl fmt::Debug for GetInstanceRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GetInstanceRequest")
            .field("scope_digest", &self.scope.digest())
            .field("request_digest", &self.request_digest)
            .finish_non_exhaustive()
    }
}
impl GetInstanceRequest {
    pub fn new(scope: &GcpMemorystoreScope) -> Result<Self> {
        scope.validate()?;
        let request_digest = Digest::from_parts(
            "gcp-memorystore-get-request/v1",
            &[
                ("scope", scope.digest().as_str().to_owned()),
                ("project", scope.gcp_project().digest().as_str().to_owned()),
                ("location", scope.location().digest().as_str().to_owned()),
                ("instance", scope.instance().digest().as_str().to_owned()),
                ("api", scope.api_digest().as_str().to_owned()),
                ("permission", scope.permission_digest().as_str().to_owned()),
            ],
        );
        let path_digest = Digest::from_parts(
            "gcp-memorystore-get-path/v1",
            &[
                ("name", scope.resource_name_digest().as_str().to_owned()),
                ("api", API_REVISION.to_owned()),
            ],
        );
        let recorded = RecordedRequest::from_parts(
            GcpMemorystoreOperation::InstancesGet,
            request_digest.clone(),
            path_digest,
            scope,
            None,
        );
        Ok(Self {
            scope: scope.clone(),
            request_digest,
            recorded,
        })
    }
    pub fn scope(&self) -> &GcpMemorystoreScope {
        &self.scope
    }
    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }
    pub fn recorded_request(&self) -> RecordedRequest {
        self.recorded.clone()
    }
    pub(crate) fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        self.recorded.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListInstancesResponse {
    pub instances: Vec<InstanceSummary>,
    pub next_page_token: Option<OpaquePageToken>,
    pub unreachable: Vec<Digest>,
    pub response_bytes: u64,
    pub request_receipt: RequestReceipt,
    pub cost_receipt: CostReceipt,
    pub evidence_digest: Digest,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}
impl ListInstancesResponse {
    pub fn new(
        request: &ListInstancesRequest,
        instances: Vec<InstanceSummary>,
        next_page_token: Option<OpaquePageToken>,
        unreachable: impl IntoIterator<Item = String>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        request.validate()?;
        if instances.len() > MAX_LIST_ITEMS {
            return Err(GcpMemorystoreError::InvalidResponse);
        }
        let unreachable = unreachable
            .into_iter()
            .map(Digest::from_text)
            .collect::<Vec<_>>();
        let request_receipt = request.recorded_request().receipt();
        let cost_receipt = CostReceipt::new(
            GcpMemorystoreOperation::InstancesList.as_str(),
            response_bytes,
        )?;
        let evidence_digest = list_evidence_digest(
            request,
            &instances,
            next_page_token.as_ref(),
            &unreachable,
            response_bytes,
            provenance,
        );
        Ok(Self {
            instances,
            next_page_token,
            unreachable,
            response_bytes,
            request_receipt,
            cost_receipt,
            evidence_digest,
            provenance,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        })
    }
    pub fn unreachable_count(&self) -> usize {
        self.unreachable.len()
    }
    pub(crate) fn validate_integrity(
        &self,
        request: &ListInstancesRequest,
        expected: TransportProvenance,
    ) -> Result<()> {
        request.validate()?;
        self.request_receipt.validate()?;
        self.cost_receipt.validate()?;
        if self.request_receipt != request.recorded_request().receipt()
            || self.provenance != expected
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.instances.len() > MAX_LIST_ITEMS
        {
            return Err(GcpMemorystoreError::TamperedEvidence);
        }
        if self.response_bytes > MAX_RESPONSE_BYTES {
            return Err(GcpMemorystoreError::TruncatedEvidence);
        }
        if self
            .next_page_token
            .as_ref()
            .is_some_and(|token| token.validate().is_err())
        {
            return Err(GcpMemorystoreError::TamperedEvidence);
        }
        for digest in &self.unreachable {
            digest.validate()?;
        }
        if self.evidence_digest
            != list_evidence_digest(
                request,
                &self.instances,
                self.next_page_token.as_ref(),
                &self.unreachable,
                self.response_bytes,
                self.provenance,
            )
        {
            return Err(GcpMemorystoreError::TamperedEvidence);
        }
        Ok(())
    }
}
fn list_evidence_digest(
    request: &ListInstancesRequest,
    instances: &[InstanceSummary],
    next: Option<&OpaquePageToken>,
    unreachable: &[Digest],
    response_bytes: u64,
    provenance: TransportProvenance,
) -> Digest {
    Digest::from_parts(
        "gcp-memorystore-list-evidence/v1",
        &[
            ("request", request.request_digest().as_str().to_owned()),
            (
                "instances",
                instances
                    .iter()
                    .map(InstanceSummary::identity_digest)
                    .map(|value| value.as_str().to_owned())
                    .collect::<Vec<_>>()
                    .join("\n"),
            ),
            (
                "next",
                optional_digest(next.map(OpaquePageToken::digest).as_ref()),
            ),
            (
                "unreachable",
                unreachable
                    .iter()
                    .map(|value| value.as_str().to_owned())
                    .collect::<Vec<_>>()
                    .join("\n"),
            ),
            ("response_bytes", response_bytes.to_string()),
            ("provenance", format!("{provenance:?}")),
        ],
    )
}

#[derive(Clone, Eq, PartialEq)]
pub struct GetInstanceResponse {
    pub instance: InstanceInput,
    pub response_bytes: u64,
    pub request_receipt: RequestReceipt,
    pub cost_receipt: CostReceipt,
    pub evidence_digest: Digest,
    pub provenance: TransportProvenance,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
}
impl fmt::Debug for GetInstanceResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GetInstanceResponse")
            .field("instance", &self.instance)
            .field("response_bytes", &self.response_bytes)
            .field("request_receipt", &self.request_receipt)
            .field("cost_receipt", &self.cost_receipt)
            .field("evidence_digest", &self.evidence_digest)
            .field("provenance", &self.provenance)
            .field("connected", &self.connected)
            .field("native", &self.native)
            .field("first_party", &self.first_party)
            .field("provider_receipt", &self.provider_receipt)
            .finish()
    }
}
impl GetInstanceResponse {
    pub fn new(
        request: &GetInstanceRequest,
        instance: InstanceInput,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        request.validate()?;
        let request_receipt = request.recorded_request().receipt();
        let cost_receipt = CostReceipt::new(
            GcpMemorystoreOperation::InstancesGet.as_str(),
            response_bytes,
        )?;
        let evidence_digest = Digest::from_parts(
            "gcp-memorystore-get-evidence/v1",
            &[
                ("request", request.request_digest().as_str().to_owned()),
                (
                    "resource",
                    Digest::from_text(instance.resource_name())
                        .as_str()
                        .to_owned(),
                ),
                ("state", format!("{:?}", instance.state())),
                ("response_bytes", response_bytes.to_string()),
                ("provenance", format!("{provenance:?}")),
            ],
        );
        Ok(Self {
            instance,
            response_bytes,
            request_receipt,
            cost_receipt,
            evidence_digest,
            provenance,
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
        })
    }
    pub(crate) fn validate_integrity(
        &self,
        request: &GetInstanceRequest,
        expected: TransportProvenance,
    ) -> Result<()> {
        request.validate()?;
        self.request_receipt.validate()?;
        self.cost_receipt.validate()?;
        if self.request_receipt != request.recorded_request().receipt()
            || self.provenance != expected
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
        {
            return Err(GcpMemorystoreError::TamperedEvidence);
        }
        if self.response_bytes > MAX_RESPONSE_BYTES {
            return Err(GcpMemorystoreError::TruncatedEvidence);
        }
        let expected_digest = Digest::from_parts(
            "gcp-memorystore-get-evidence/v1",
            &[
                ("request", request.request_digest().as_str().to_owned()),
                (
                    "resource",
                    Digest::from_text(self.instance.resource_name())
                        .as_str()
                        .to_owned(),
                ),
                ("state", format!("{:?}", self.instance.state())),
                ("response_bytes", self.response_bytes.to_string()),
                ("provenance", format!("{:?}", self.provenance)),
            ],
        );
        if self.evidence_digest == expected_digest {
            Ok(())
        } else {
            Err(GcpMemorystoreError::TamperedEvidence)
        }
    }
    pub(crate) fn projection(
        &self,
        scope: &GcpMemorystoreScope,
    ) -> Result<crate::model::RedisInstanceProjection> {
        self.instance.projection(scope)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcpMemorystoreProviderDefinition {
    pub schema_version: String,
    pub provider_id: String,
    pub provider_version: String,
    pub provider_revision: u64,
    pub api_revision: String,
    pub contract_version: String,
    pub permission_digest: Digest,
    pub provider_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub external_writes: bool,
}
impl GcpMemorystoreProviderDefinition {
    pub fn new(
        provider_revision: u64,
        provider_version: impl Into<String>,
        permissions: &crate::model::PermissionSnapshot,
    ) -> Result<Self> {
        let provider_version = provider_version.into();
        permissions.validate()?;
        if provider_revision == 0 || provider_version.is_empty() {
            return Err(GcpMemorystoreError::ProviderDrift);
        }
        let provider_digest = provider_digest(
            PROVIDER_ID,
            &provider_version,
            provider_revision,
            API_REVISION,
            CONTRACT_VERSION,
            permissions.digest(),
        );
        Ok(Self {
            schema_version: crate::CONTRACT_SCHEMA.to_owned(),
            provider_id: PROVIDER_ID.to_owned(),
            provider_version,
            provider_revision,
            api_revision: API_REVISION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            permission_digest: permissions.digest().clone(),
            provider_digest,
            connected: false,
            native: false,
            first_party: false,
            external_writes: false,
        })
    }
    pub fn baseline(permissions: &crate::model::PermissionSnapshot) -> Result<Self> {
        Self::new(1, PLUGIN_VERSION, permissions)
    }
    pub fn provider_digest(&self) -> &Digest {
        &self.provider_digest
    }
    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }
    pub const fn provider_revision(&self) -> u64 {
        self.provider_revision
    }
    pub fn validate(&self) -> Result<()> {
        if self.provider_id != PROVIDER_ID
            || self.provider_version.is_empty()
            || self.provider_revision == 0
            || self.api_revision != API_REVISION
            || self.contract_version != CONTRACT_VERSION
            || self.connected
            || self.native
            || self.first_party
            || self.external_writes
            || self.provider_digest
                != provider_digest(
                    &self.provider_id,
                    &self.provider_version,
                    self.provider_revision,
                    &self.api_revision,
                    &self.contract_version,
                    &self.permission_digest,
                )
        {
            Err(GcpMemorystoreError::ProviderDrift)
        } else {
            self.permission_digest.validate()
        }
    }
}
fn provider_digest(
    id: &str,
    version: &str,
    revision: u64,
    api: &str,
    contract: &str,
    permission: &Digest,
) -> Digest {
    Digest::from_parts(
        "gcp-memorystore-provider-definition/v1",
        &[
            ("id", id.to_owned()),
            ("version", version.to_owned()),
            ("revision", revision.to_string()),
            ("api", api.to_owned()),
            ("contract", contract.to_owned()),
            ("permission", permission.as_str().to_owned()),
            ("connected", "false".to_owned()),
            ("native", "false".to_owned()),
            ("first_party", "false".to_owned()),
        ],
    )
}

pub trait GcpMemorystoreTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;
    fn list_instances(
        &mut self,
        request: &ListInstancesRequest,
    ) -> std::result::Result<ListInstancesResponse, GcpMemorystoreTransportError>;
    fn get_instance(
        &mut self,
        request: &GetInstanceRequest,
    ) -> std::result::Result<GetInstanceResponse, GcpMemorystoreTransportError>;
}

pub struct GcpMemorystoreAdminProvider<T> {
    transport: T,
    definition: GcpMemorystoreProviderDefinition,
}
pub type GcpMemorystoreProvider<T> = GcpMemorystoreAdminProvider<T>;
impl<T: GcpMemorystoreTransport> fmt::Debug for GcpMemorystoreAdminProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GcpMemorystoreAdminProvider")
            .field("definition", &self.definition)
            .field("provenance", &self.transport.provenance())
            .finish()
    }
}
impl<T: GcpMemorystoreTransport> GcpMemorystoreAdminProvider<T> {
    pub fn new(transport: T) -> Result<Self> {
        Self::with_identity(transport, 1, PLUGIN_VERSION)
    }
    pub fn with_identity(transport: T, revision: u64, version: impl Into<String>) -> Result<Self> {
        let permissions = crate::model::PermissionSnapshot::least_privilege();
        Self::with_permission_snapshot(transport, revision, version, &permissions)
    }
    pub fn with_permission_snapshot(
        transport: T,
        revision: u64,
        version: impl Into<String>,
        permissions: &crate::model::PermissionSnapshot,
    ) -> Result<Self> {
        let definition = GcpMemorystoreProviderDefinition::new(revision, version, permissions)?;
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
        })
    }
    pub fn definition(&self) -> &GcpMemorystoreProviderDefinition {
        &self.definition
    }
    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }
    pub fn list_instances(
        &mut self,
        request: &ListInstancesRequest,
    ) -> std::result::Result<ListInstancesResponse, GcpMemorystoreTransportError> {
        let response = self.transport.list_instances(request)?;
        response
            .validate_integrity(request, self.provenance())
            .map_err(map_response_error)?;
        Ok(response)
    }
    pub fn get_instance(
        &mut self,
        request: &GetInstanceRequest,
    ) -> std::result::Result<GetInstanceResponse, GcpMemorystoreTransportError> {
        let response = self.transport.get_instance(request)?;
        response
            .validate_integrity(request, self.provenance())
            .map_err(map_response_error)?;
        Ok(response)
    }
    pub fn into_transport(self) -> T {
        self.transport
    }
    pub fn from_registration(
        registration: &crate::service::GcpMemorystoreInstanceRegistration,
        transport: T,
    ) -> Result<Self> {
        let provider = Self::with_identity(
            transport,
            registration.provider_revision(),
            registration.provider_version().to_owned(),
        )?;
        if provider.definition.provider_digest == *registration.provider_digest() {
            Ok(provider)
        } else {
            Err(GcpMemorystoreError::ProviderDrift)
        }
    }
}
fn map_response_error(error: GcpMemorystoreError) -> GcpMemorystoreTransportError {
    match error {
        GcpMemorystoreError::TruncatedEvidence => GcpMemorystoreTransportError::Truncated,
        GcpMemorystoreError::PaginationLoop => GcpMemorystoreTransportError::PaginationLoop,
        GcpMemorystoreError::ScopeDrift | GcpMemorystoreError::ApiDrift => {
            GcpMemorystoreTransportError::ApiDrift
        }
        GcpMemorystoreError::TamperedEvidence => GcpMemorystoreTransportError::Tampered,
        _ => GcpMemorystoreTransportError::InvalidResponse,
    }
}
impl Default for GcpMemorystoreAdminProvider<BlockedEnvTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvTransport).expect("blocked provider")
    }
}

#[derive(Clone, Debug)]
pub struct RecordingTransport {
    provenance: TransportProvenance,
    list_responses:
        VecDeque<std::result::Result<ListInstancesResponse, GcpMemorystoreTransportError>>,
    get_responses: VecDeque<std::result::Result<GetInstanceResponse, GcpMemorystoreTransportError>>,
    requests: Vec<RecordedRequest>,
}
impl RecordingTransport {
    pub fn new(provenance: TransportProvenance) -> Self {
        Self {
            provenance,
            list_responses: VecDeque::new(),
            get_responses: VecDeque::new(),
            requests: Vec::new(),
        }
    }
    pub fn push_list_response(
        &mut self,
        response: std::result::Result<ListInstancesResponse, GcpMemorystoreTransportError>,
    ) {
        self.list_responses.push_back(response);
    }
    pub fn push_get_response(
        &mut self,
        response: std::result::Result<GetInstanceResponse, GcpMemorystoreTransportError>,
    ) {
        self.get_responses.push_back(response);
    }
    pub fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }
}
impl Default for RecordingTransport {
    fn default() -> Self {
        Self::new(TransportProvenance::Recording)
    }
}
impl GcpMemorystoreTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }
    fn list_instances(
        &mut self,
        request: &ListInstancesRequest,
    ) -> std::result::Result<ListInstancesResponse, GcpMemorystoreTransportError> {
        self.requests.push(request.recorded_request());
        self.list_responses
            .pop_front()
            .unwrap_or(Err(GcpMemorystoreTransportError::InvalidResponse))
    }
    fn get_instance(
        &mut self,
        request: &GetInstanceRequest,
    ) -> std::result::Result<GetInstanceResponse, GcpMemorystoreTransportError> {
        self.requests.push(request.recorded_request());
        self.get_responses
            .pop_front()
            .unwrap_or(Err(GcpMemorystoreTransportError::InvalidResponse))
    }
}
pub type FakeGcpMemorystoreTransport = RecordingTransport;

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    scope: GcpMemorystoreScope,
}
impl FixtureTransport {
    pub fn for_scope(scope: &GcpMemorystoreScope) -> Self {
        Self {
            scope: scope.clone(),
        }
    }
    pub fn new(scope: GcpMemorystoreScope) -> Self {
        Self { scope }
    }
}
impl GcpMemorystoreTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }
    fn list_instances(
        &mut self,
        request: &ListInstancesRequest,
    ) -> std::result::Result<ListInstancesResponse, GcpMemorystoreTransportError> {
        ListInstancesResponse::new(
            request,
            vec![InstanceSummary::fixture(&self.scope)],
            None,
            Vec::<String>::new(),
            2_048,
            TransportProvenance::Fixture,
        )
        .map_err(|_| GcpMemorystoreTransportError::InvalidResponse)
    }
    fn get_instance(
        &mut self,
        request: &GetInstanceRequest,
    ) -> std::result::Result<GetInstanceResponse, GcpMemorystoreTransportError> {
        GetInstanceResponse::new(
            request,
            InstanceInput::fixture(&self.scope),
            8_192,
            TransportProvenance::Fixture,
        )
        .map_err(|_| GcpMemorystoreTransportError::InvalidResponse)
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    inner: FixtureTransport,
}
impl LoopbackTransport {
    pub fn for_scope(scope: &GcpMemorystoreScope) -> Self {
        Self {
            inner: FixtureTransport::for_scope(scope),
        }
    }
}
impl GcpMemorystoreTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }
    fn list_instances(
        &mut self,
        request: &ListInstancesRequest,
    ) -> std::result::Result<ListInstancesResponse, GcpMemorystoreTransportError> {
        ListInstancesResponse::new(
            request,
            vec![InstanceSummary::fixture(&self.inner.scope)],
            None,
            Vec::<String>::new(),
            2_048,
            TransportProvenance::Loopback,
        )
        .map_err(|_| GcpMemorystoreTransportError::InvalidResponse)
    }
    fn get_instance(
        &mut self,
        request: &GetInstanceRequest,
    ) -> std::result::Result<GetInstanceResponse, GcpMemorystoreTransportError> {
        GetInstanceResponse::new(
            request,
            InstanceInput::fixture(&self.inner.scope),
            8_192,
            TransportProvenance::Loopback,
        )
        .map_err(|_| GcpMemorystoreTransportError::InvalidResponse)
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvTransport;
impl GcpMemorystoreTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }
    fn list_instances(
        &mut self,
        _request: &ListInstancesRequest,
    ) -> std::result::Result<ListInstancesResponse, GcpMemorystoreTransportError> {
        Err(GcpMemorystoreTransportError::BlockedEnv)
    }
    fn get_instance(
        &mut self,
        _request: &GetInstanceRequest,
    ) -> std::result::Result<GetInstanceResponse, GcpMemorystoreTransportError> {
        Err(GcpMemorystoreTransportError::BlockedEnv)
    }
}
