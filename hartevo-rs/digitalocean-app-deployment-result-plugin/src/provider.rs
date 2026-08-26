use std::{
    collections::{BTreeMap, VecDeque},
    fmt,
};

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{Value, json};

use crate::error::{DigitalOceanAppDeploymentResultError, DigitalOceanTransportError, Result};
use crate::model::{
    AppProjection, ComponentProjection, ComponentStatus, CostReceipt, DeploymentPhase,
    DeploymentProjection, Digest, DigitalOceanAppDeploymentScope, EventProjection,
    HealthComponentProjection, HealthProjection, HealthState, RequestReceipt, TransportProvenance,
    bound_components, bound_events, percent_encode, validate_page_number, validate_page_size,
};
use crate::{API_REVISION, MAX_RESPONSE_BYTES, PROVIDER_ID, PROVIDER_VERSION};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum DigitalOceanAppsOperation {
    GetApp,
    ListDeployments,
    GetDeployment,
    ListEvents,
    GetAppHealth,
}

impl DigitalOceanAppsOperation {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GetApp => "GetApp",
            Self::ListDeployments => "ListDeployments",
            Self::GetDeployment => "GetDeployment",
            Self::ListEvents => "ListEvents",
            Self::GetAppHealth => "GetAppHealth",
        }
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PageCursor {
    page: u32,
    page_size: u16,
    scope_digest: Digest,
    page_digest: Digest,
}

impl fmt::Debug for PageCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PageCursor")
            .field("page", &self.page)
            .field("page_size", &self.page_size)
            .field("scope_digest", &self.scope_digest)
            .field("page_digest", &self.page_digest)
            .finish()
    }
}

impl PageCursor {
    pub fn new(page: u32, page_size: u16, scope: &DigitalOceanAppDeploymentScope) -> Result<Self> {
        validate_page_number(page)?;
        validate_page_size(page_size)?;
        let scope_digest = scope.digest();
        let page_digest = Digest::from_parts(
            "digitalocean-page-cursor/v1",
            &[
                ("scope", scope_digest.as_str().to_owned()),
                ("page", page.to_string()),
                ("page_size", page_size.to_string()),
            ],
        );
        Ok(Self {
            page,
            page_size,
            scope_digest,
            page_digest,
        })
    }

    #[must_use]
    pub const fn page(&self) -> u32 {
        self.page
    }
    #[must_use]
    pub const fn page_size(&self) -> u16 {
        self.page_size
    }
    #[must_use]
    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }
    #[must_use]
    pub fn page_digest(&self) -> &Digest {
        &self.page_digest
    }

    pub fn validate(&self, scope: &DigitalOceanAppDeploymentScope) -> Result<()> {
        if self.scope_digest != scope.digest()
            || self.page_digest
                != Digest::from_parts(
                    "digitalocean-page-cursor/v1",
                    &[
                        ("scope", self.scope_digest.as_str().to_owned()),
                        ("page", self.page.to_string()),
                        ("page_size", self.page_size.to_string()),
                    ],
                )
        {
            return Err(DigitalOceanAppDeploymentResultError::CursorMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: DigitalOceanAppsOperation,
    pub request_digest: Digest,
    pub path_digest: Digest,
    pub scope_digest: Digest,
    pub page_digest: Option<Digest>,
}

impl RecordedRequest {
    #[must_use]
    pub fn receipt(&self) -> RequestReceipt {
        RequestReceipt::new(
            self.operation.as_str(),
            self.request_digest.clone(),
            self.path_digest.clone(),
            self.scope_digest.clone(),
            self.page_digest.clone(),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetAppRequest {
    pub scope_digest: Digest,
    pub consent_digest: Digest,
    pub secret_reference_digest: Digest,
    pub request_digest: Digest,
}

impl GetAppRequest {
    pub fn for_scope(
        scope: &DigitalOceanAppDeploymentScope,
        secret_reference_digest: &Digest,
        consent_digest: &Digest,
    ) -> Self {
        let scope_digest = scope.digest();
        let request_digest = request_digest(
            DigitalOceanAppsOperation::GetApp,
            scope_digest.as_str(),
            None,
            secret_reference_digest,
            consent_digest,
        );
        Self {
            scope_digest,
            consent_digest: consent_digest.clone(),
            secret_reference_digest: secret_reference_digest.clone(),
            request_digest,
        }
    }

    #[must_use]
    pub fn scope(&self) -> &Digest {
        &self.scope_digest
    }

    #[must_use]
    pub fn path_and_query(&self, scope: &DigitalOceanAppDeploymentScope) -> String {
        format!("/v2/apps/{}", percent_encode(scope.app().as_str()))
    }

    #[must_use]
    pub fn recorded_request(&self, scope: &DigitalOceanAppDeploymentScope) -> RecordedRequest {
        RecordedRequest {
            operation: DigitalOceanAppsOperation::GetApp,
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query(scope)),
            scope_digest: self.scope_digest.clone(),
            page_digest: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListDeploymentsRequest {
    pub page_size: u16,
    pub cursor: Option<PageCursor>,
    pub scope_digest: Digest,
    pub consent_digest: Digest,
    pub secret_reference_digest: Digest,
    pub request_digest: Digest,
}

impl ListDeploymentsRequest {
    pub fn first(
        scope: &DigitalOceanAppDeploymentScope,
        page_size: u16,
        secret_reference_digest: &Digest,
        consent_digest: &Digest,
    ) -> Result<Self> {
        Self::new(
            scope,
            page_size,
            None,
            secret_reference_digest,
            consent_digest,
        )
    }

    pub fn new(
        scope: &DigitalOceanAppDeploymentScope,
        page_size: u16,
        cursor: Option<PageCursor>,
        secret_reference_digest: &Digest,
        consent_digest: &Digest,
    ) -> Result<Self> {
        validate_page_size(page_size)?;
        if let Some(cursor) = &cursor {
            cursor.validate(scope)?;
            if cursor.page_size() != page_size {
                return Err(DigitalOceanAppDeploymentResultError::CursorMismatch);
            }
        }
        let scope_digest = scope.digest();
        let page = cursor.as_ref().map(PageCursor::page);
        let request_digest = request_digest(
            DigitalOceanAppsOperation::ListDeployments,
            scope_digest.as_str(),
            page,
            secret_reference_digest,
            consent_digest,
        );
        Ok(Self {
            page_size,
            cursor,
            scope_digest,
            consent_digest: consent_digest.clone(),
            secret_reference_digest: secret_reference_digest.clone(),
            request_digest,
        })
    }

    #[must_use]
    pub fn page_number(&self) -> u32 {
        self.cursor.as_ref().map_or(1, PageCursor::page)
    }
    #[must_use]
    pub fn path_and_query(&self, scope: &DigitalOceanAppDeploymentScope) -> String {
        format!(
            "/v2/apps/{}/deployments?page={}&per_page={}",
            percent_encode(scope.app().as_str()),
            self.page_number(),
            self.page_size
        )
    }
    #[must_use]
    pub fn recorded_request(&self, scope: &DigitalOceanAppDeploymentScope) -> RecordedRequest {
        RecordedRequest {
            operation: DigitalOceanAppsOperation::ListDeployments,
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query(scope)),
            scope_digest: self.scope_digest.clone(),
            page_digest: self
                .cursor
                .as_ref()
                .map(|cursor| cursor.page_digest().clone()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetDeploymentRequest {
    pub scope_digest: Digest,
    pub consent_digest: Digest,
    pub secret_reference_digest: Digest,
    pub request_digest: Digest,
}

impl GetDeploymentRequest {
    pub fn for_scope(
        scope: &DigitalOceanAppDeploymentScope,
        secret_reference_digest: &Digest,
        consent_digest: &Digest,
    ) -> Self {
        let scope_digest = scope.digest();
        let request_digest = request_digest(
            DigitalOceanAppsOperation::GetDeployment,
            scope_digest.as_str(),
            None,
            secret_reference_digest,
            consent_digest,
        );
        Self {
            scope_digest,
            consent_digest: consent_digest.clone(),
            secret_reference_digest: secret_reference_digest.clone(),
            request_digest,
        }
    }

    #[must_use]
    pub fn path_and_query(&self, scope: &DigitalOceanAppDeploymentScope) -> String {
        format!(
            "/v2/apps/{}/deployments/{}",
            percent_encode(scope.app().as_str()),
            percent_encode(scope.deployment().as_str())
        )
    }
    #[must_use]
    pub fn recorded_request(&self, scope: &DigitalOceanAppDeploymentScope) -> RecordedRequest {
        RecordedRequest {
            operation: DigitalOceanAppsOperation::GetDeployment,
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query(scope)),
            scope_digest: self.scope_digest.clone(),
            page_digest: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListEventsRequest {
    pub page_size: u16,
    pub cursor: Option<PageCursor>,
    pub scope_digest: Digest,
    pub consent_digest: Digest,
    pub secret_reference_digest: Digest,
    pub request_digest: Digest,
}

impl ListEventsRequest {
    pub fn first(
        scope: &DigitalOceanAppDeploymentScope,
        page_size: u16,
        secret_reference_digest: &Digest,
        consent_digest: &Digest,
    ) -> Result<Self> {
        Self::new(
            scope,
            page_size,
            None,
            secret_reference_digest,
            consent_digest,
        )
    }

    pub fn new(
        scope: &DigitalOceanAppDeploymentScope,
        page_size: u16,
        cursor: Option<PageCursor>,
        secret_reference_digest: &Digest,
        consent_digest: &Digest,
    ) -> Result<Self> {
        validate_page_size(page_size)?;
        if let Some(cursor) = &cursor {
            cursor.validate(scope)?;
            if cursor.page_size() != page_size {
                return Err(DigitalOceanAppDeploymentResultError::CursorMismatch);
            }
        }
        let scope_digest = scope.digest();
        let page = cursor.as_ref().map(PageCursor::page);
        let request_digest = request_digest(
            DigitalOceanAppsOperation::ListEvents,
            scope_digest.as_str(),
            page,
            secret_reference_digest,
            consent_digest,
        );
        Ok(Self {
            page_size,
            cursor,
            scope_digest,
            consent_digest: consent_digest.clone(),
            secret_reference_digest: secret_reference_digest.clone(),
            request_digest,
        })
    }

    #[must_use]
    pub fn page_number(&self) -> u32 {
        self.cursor.as_ref().map_or(1, PageCursor::page)
    }
    #[must_use]
    pub fn path_and_query(&self, scope: &DigitalOceanAppDeploymentScope) -> String {
        format!(
            "/v2/apps/{}/events?page={}&per_page={}",
            percent_encode(scope.app().as_str()),
            self.page_number(),
            self.page_size
        )
    }
    #[must_use]
    pub fn recorded_request(&self, scope: &DigitalOceanAppDeploymentScope) -> RecordedRequest {
        RecordedRequest {
            operation: DigitalOceanAppsOperation::ListEvents,
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query(scope)),
            scope_digest: self.scope_digest.clone(),
            page_digest: self
                .cursor
                .as_ref()
                .map(|cursor| cursor.page_digest().clone()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetAppHealthRequest {
    pub scope_digest: Digest,
    pub consent_digest: Digest,
    pub secret_reference_digest: Digest,
    pub request_digest: Digest,
}

impl GetAppHealthRequest {
    pub fn for_scope(
        scope: &DigitalOceanAppDeploymentScope,
        secret_reference_digest: &Digest,
        consent_digest: &Digest,
    ) -> Self {
        let scope_digest = scope.digest();
        let request_digest = request_digest(
            DigitalOceanAppsOperation::GetAppHealth,
            scope_digest.as_str(),
            None,
            secret_reference_digest,
            consent_digest,
        );
        Self {
            scope_digest,
            consent_digest: consent_digest.clone(),
            secret_reference_digest: secret_reference_digest.clone(),
            request_digest,
        }
    }

    #[must_use]
    pub fn path_and_query(&self, scope: &DigitalOceanAppDeploymentScope) -> String {
        format!("/v2/apps/{}/health", percent_encode(scope.app().as_str()))
    }
    #[must_use]
    pub fn recorded_request(&self, scope: &DigitalOceanAppDeploymentScope) -> RecordedRequest {
        RecordedRequest {
            operation: DigitalOceanAppsOperation::GetAppHealth,
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(self.path_and_query(scope)),
            scope_digest: self.scope_digest.clone(),
            page_digest: None,
        }
    }
}

fn request_digest(
    operation: DigitalOceanAppsOperation,
    scope_digest: &str,
    page: Option<u32>,
    secret_reference_digest: &Digest,
    consent_digest: &Digest,
) -> Digest {
    Digest::from_parts(
        "digitalocean-request/v1",
        &[
            ("operation", operation.as_str().to_owned()),
            ("scope", scope_digest.to_owned()),
            (
                "page",
                page.map_or_else(|| "none".to_owned(), |value| value.to_string()),
            ),
            ("secret", secret_reference_digest.as_str().to_owned()),
            ("consent", consent_digest.as_str().to_owned()),
        ],
    )
}

#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct DigitalOceanAppsResponse {
    pub status: u16,
    #[serde(skip)]
    body: Vec<u8>,
    pub provenance: TransportProvenance,
    pub declared_response_digest: Option<Digest>,
    pub bound_request_digest: Option<Digest>,
}

impl fmt::Debug for DigitalOceanAppsResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DigitalOceanAppsResponse")
            .field("status", &self.status)
            .field("body_digest", &self.response_digest())
            .field("body_bytes", &self.body.len())
            .field("provenance", &self.provenance)
            .field("declared_response_digest", &self.declared_response_digest)
            .field("bound_request_digest", &self.bound_request_digest)
            .finish()
    }
}

impl DigitalOceanAppsResponse {
    #[must_use]
    pub fn json<T: Serialize>(status: u16, value: &T, provenance: TransportProvenance) -> Self {
        Self::new(
            status,
            serde_json::to_vec(value).expect("DigitalOcean fixture serializes"),
            provenance,
        )
    }

    #[must_use]
    pub fn new(status: u16, body: Vec<u8>, provenance: TransportProvenance) -> Self {
        Self {
            status,
            body,
            provenance,
            declared_response_digest: None,
            bound_request_digest: None,
        }
    }

    #[must_use]
    pub fn with_declared_digest(mut self, digest: Digest) -> Self {
        self.declared_response_digest = Some(digest);
        self
    }

    #[must_use]
    pub fn with_request_digest(mut self, digest: Digest) -> Self {
        self.bound_request_digest = Some(digest);
        self
    }

    #[must_use]
    pub fn response_digest(&self) -> Digest {
        Digest::from_bytes(&self.body)
    }
    #[must_use]
    pub const fn response_bytes(&self) -> usize {
        self.body.len()
    }
    #[must_use]
    pub(crate) fn body(&self) -> &[u8] {
        &self.body
    }

    pub fn validate_integrity(&self, request_digest: &Digest) -> Result<()> {
        if self.response_bytes() > MAX_RESPONSE_BYTES as usize
            || self
                .bound_request_digest
                .as_ref()
                .is_some_and(|digest| digest != request_digest)
            || self
                .declared_response_digest
                .as_ref()
                .is_some_and(|digest| digest != &self.response_digest())
        {
            return Err(DigitalOceanAppDeploymentResultError::TamperedEvidence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppRead {
    pub projection: AppProjection,
    pub response_digest: Digest,
    pub request_receipt: RequestReceipt,
    pub cost_receipt: CostReceipt,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentPageRead {
    pub deployments: Vec<DeploymentProjection>,
    pub next_page: Option<u32>,
    pub page_digest: Digest,
    pub response_digest: Digest,
    pub request_receipt: RequestReceipt,
    pub cost_receipt: CostReceipt,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentRead {
    pub projection: DeploymentProjection,
    pub response_digest: Digest,
    pub request_receipt: RequestReceipt,
    pub cost_receipt: CostReceipt,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EventsRead {
    pub events: Vec<EventProjection>,
    pub next_page: Option<u32>,
    pub page_digest: Digest,
    pub response_digest: Digest,
    pub request_receipt: RequestReceipt,
    pub cost_receipt: CostReceipt,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthRead {
    pub projection: HealthProjection,
    pub response_digest: Digest,
    pub request_receipt: RequestReceipt,
    pub cost_receipt: CostReceipt,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DigitalOceanAppsProviderDefinition {
    pub provider_id: String,
    pub provider_revision: u64,
    pub provider_release: String,
    pub api_revision: String,
    pub provider_digest: Digest,
    pub api_digest: Digest,
}

impl DigitalOceanAppsProviderDefinition {
    pub fn new(provider_revision: u64, provider_release: impl Into<String>) -> Result<Self> {
        let provider_release = provider_release.into();
        if provider_revision == 0 || provider_release.is_empty() {
            return Err(DigitalOceanAppDeploymentResultError::ProviderDrift);
        }
        let provider_digest = Digest::from_parts(
            "digitalocean-provider/v1",
            &[
                ("id", PROVIDER_ID.to_owned()),
                ("revision", provider_revision.to_string()),
                ("release", provider_release.clone()),
                ("api", API_REVISION.to_owned()),
            ],
        );
        Ok(Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_revision,
            provider_release,
            api_revision: API_REVISION.to_owned(),
            provider_digest,
            api_digest: Digest::from_text(API_REVISION),
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.provider_id != PROVIDER_ID
            || self.provider_revision == 0
            || self.provider_release != PROVIDER_VERSION
            || self.api_revision != API_REVISION
            || self.provider_digest
                != Digest::from_parts(
                    "digitalocean-provider/v1",
                    &[
                        ("id", self.provider_id.clone()),
                        ("revision", self.provider_revision.to_string()),
                        ("release", self.provider_release.clone()),
                        ("api", self.api_revision.clone()),
                    ],
                )
            || self.api_digest != Digest::from_text(API_REVISION)
        {
            return Err(DigitalOceanAppDeploymentResultError::ProviderDrift);
        }
        Ok(())
    }
}

pub trait DigitalOceanAppsTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;
    fn get_app(
        &mut self,
        request: &GetAppRequest,
    ) -> std::result::Result<DigitalOceanAppsResponse, DigitalOceanTransportError>;
    fn list_deployments(
        &mut self,
        request: &ListDeploymentsRequest,
    ) -> std::result::Result<DigitalOceanAppsResponse, DigitalOceanTransportError>;
    fn get_deployment(
        &mut self,
        request: &GetDeploymentRequest,
    ) -> std::result::Result<DigitalOceanAppsResponse, DigitalOceanTransportError>;
    fn list_events(
        &mut self,
        request: &ListEventsRequest,
    ) -> std::result::Result<DigitalOceanAppsResponse, DigitalOceanTransportError>;
    fn get_app_health(
        &mut self,
        request: &GetAppHealthRequest,
    ) -> std::result::Result<DigitalOceanAppsResponse, DigitalOceanTransportError>;
}

pub struct DigitalOceanAppsProvider<T: DigitalOceanAppsTransport> {
    transport: T,
    definition: DigitalOceanAppsProviderDefinition,
}

impl<T: DigitalOceanAppsTransport> fmt::Debug for DigitalOceanAppsProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DigitalOceanAppsProvider")
            .field("definition", &self.definition)
            .field("provenance", &self.provenance())
            .finish()
    }
}

impl<T: DigitalOceanAppsTransport> DigitalOceanAppsProvider<T> {
    pub fn new(transport: T) -> Result<Self> {
        Self::with_identity(transport, 1, PROVIDER_VERSION)
    }

    pub fn with_identity(
        transport: T,
        provider_revision: u64,
        provider_release: impl Into<String>,
    ) -> Result<Self> {
        Ok(Self {
            transport,
            definition: DigitalOceanAppsProviderDefinition::new(
                provider_revision,
                provider_release,
            )?,
        })
    }

    #[must_use]
    pub fn definition(&self) -> &DigitalOceanAppsProviderDefinition {
        &self.definition
    }
    #[must_use]
    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }
    #[must_use]
    pub fn provider_digest(&self) -> Digest {
        self.definition.provider_digest.clone()
    }
    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }
    #[must_use]
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }
    #[must_use]
    pub fn into_transport(self) -> T {
        self.transport
    }

    pub fn get_app(
        &mut self,
        request: &GetAppRequest,
        scope: &DigitalOceanAppDeploymentScope,
    ) -> Result<AppRead> {
        let response = self.transport.get_app(request)?;
        let recorded = request.recorded_request(scope);
        response.validate_integrity(&request.request_digest)?;
        response_for_status(response.status)?;
        let root = parse_json(&response)?;
        let object = nested_object(&root, "app").unwrap_or(&root);
        let app_id = required_text(object, "id")?;
        if app_id != scope.app().as_str() {
            return Err(DigitalOceanAppDeploymentResultError::AppDrift);
        }
        validate_optional_identity(
            object,
            "account_id",
            scope.account().as_str(),
            DigitalOceanAppDeploymentResultError::AccountDrift,
        )?;
        validate_optional_identity(
            object,
            "team_id",
            scope.team().as_str(),
            DigitalOceanAppDeploymentResultError::TeamDrift,
        )?;
        let region_value = object
            .get("region")
            .and_then(Value::as_str)
            .or_else(|| {
                object
                    .get("spec")
                    .and_then(|value| value.get("region"))
                    .and_then(Value::as_str)
            })
            .ok_or(DigitalOceanAppDeploymentResultError::RegionDrift)?;
        if region_value != scope.region().as_str() {
            return Err(DigitalOceanAppDeploymentResultError::RegionDrift);
        }
        let active_deployment_digest = object
            .get("active_deployment")
            .and_then(|value| value.get("id"))
            .and_then(Value::as_str)
            .map(|value| Digest::from_text(value.as_bytes()));
        let projection = AppProjection::new(
            scope.account().digest(),
            scope.team().digest(),
            scope.app().digest(),
            scope.region().clone(),
            active_deployment_digest,
        )?;
        let cost_receipt = CostReceipt::new(
            DigitalOceanAppsOperation::GetApp.as_str(),
            response.response_bytes() as u64,
        )?;
        Ok(AppRead {
            projection,
            response_digest: response.response_digest(),
            request_receipt: recorded.receipt(),
            cost_receipt,
        })
    }

    pub fn list_deployments(
        &mut self,
        request: &ListDeploymentsRequest,
        scope: &DigitalOceanAppDeploymentScope,
    ) -> Result<DeploymentPageRead> {
        let response = self.transport.list_deployments(request)?;
        let recorded = request.recorded_request(scope);
        response.validate_integrity(&request.request_digest)?;
        response_for_status(response.status)?;
        let root = parse_json(&response)?;
        let values = root
            .get("deployments")
            .and_then(Value::as_array)
            .ok_or(DigitalOceanAppDeploymentResultError::InvalidResponse)?;
        bound_components(values)?;
        let mut deployments = Vec::with_capacity(values.len());
        for value in values {
            deployments.push(parse_deployment(value)?);
        }
        let next_page = parse_next_page(&root)?;
        let page_digest = Digest::from_parts(
            "digitalocean-deployment-page/v1",
            &[
                ("request", request.request_digest.as_str().to_owned()),
                ("response", response.response_digest().as_str().to_owned()),
                (
                    "deployment_digests",
                    deployments
                        .iter()
                        .map(|deployment| deployment.digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "next",
                    next_page.map_or_else(|| "none".to_owned(), |page| page.to_string()),
                ),
            ],
        );
        let cost_receipt = CostReceipt::new(
            DigitalOceanAppsOperation::ListDeployments.as_str(),
            response.response_bytes() as u64,
        )?;
        Ok(DeploymentPageRead {
            deployments,
            next_page,
            page_digest,
            response_digest: response.response_digest(),
            request_receipt: recorded.receipt(),
            cost_receipt,
        })
    }

    pub fn get_deployment(
        &mut self,
        request: &GetDeploymentRequest,
        scope: &DigitalOceanAppDeploymentScope,
    ) -> Result<DeploymentRead> {
        let response = self.transport.get_deployment(request)?;
        let recorded = request.recorded_request(scope);
        response.validate_integrity(&request.request_digest)?;
        response_for_status(response.status)?;
        let root = parse_json(&response)?;
        let object = nested_object(&root, "deployment").unwrap_or(&root);
        let projection = parse_deployment(object)?;
        if projection.deployment_digest != scope.deployment().digest() {
            return Err(DigitalOceanAppDeploymentResultError::DeploymentDrift);
        }
        let cost_receipt = CostReceipt::new(
            DigitalOceanAppsOperation::GetDeployment.as_str(),
            response.response_bytes() as u64,
        )?;
        Ok(DeploymentRead {
            projection,
            response_digest: response.response_digest(),
            request_receipt: recorded.receipt(),
            cost_receipt,
        })
    }

    pub fn list_events(
        &mut self,
        request: &ListEventsRequest,
        scope: &DigitalOceanAppDeploymentScope,
    ) -> Result<EventsRead> {
        let response = self.transport.list_events(request)?;
        let recorded = request.recorded_request(scope);
        response.validate_integrity(&request.request_digest)?;
        response_for_status(response.status)?;
        let root = parse_json(&response)?;
        let values = root
            .get("events")
            .and_then(Value::as_array)
            .ok_or(DigitalOceanAppDeploymentResultError::InvalidResponse)?;
        bound_events(values)?;
        let mut events = Vec::with_capacity(values.len());
        for value in values {
            let event = parse_event(value)?;
            if event.deployment_id_digest == scope.deployment().digest() {
                events.push(event);
            }
        }
        let next_page = parse_next_page(&root)?;
        let page_digest = Digest::from_parts(
            "digitalocean-event-page/v1",
            &[
                ("request", request.request_digest.as_str().to_owned()),
                ("response", response.response_digest().as_str().to_owned()),
                (
                    "event_digests",
                    events
                        .iter()
                        .map(|event| event.event_id_digest.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "next",
                    next_page.map_or_else(|| "none".to_owned(), |page| page.to_string()),
                ),
            ],
        );
        let cost_receipt = CostReceipt::new(
            DigitalOceanAppsOperation::ListEvents.as_str(),
            response.response_bytes() as u64,
        )?;
        Ok(EventsRead {
            events,
            next_page,
            page_digest,
            response_digest: response.response_digest(),
            request_receipt: recorded.receipt(),
            cost_receipt,
        })
    }

    pub fn get_app_health(
        &mut self,
        request: &GetAppHealthRequest,
        scope: &DigitalOceanAppDeploymentScope,
    ) -> Result<HealthRead> {
        let response = self.transport.get_app_health(request)?;
        let recorded = request.recorded_request(scope);
        response.validate_integrity(&request.request_digest)?;
        response_for_status(response.status)?;
        let root = parse_json(&response)?;
        let health = nested_object(&root, "app_health").unwrap_or(&root);
        let state = health
            .get("state")
            .and_then(Value::as_str)
            .map_or(HealthState::Unknown, HealthState::parse);
        let mut components = Vec::new();
        for key in ["components", "functions_components"] {
            if let Some(values) = health.get(key).and_then(Value::as_array) {
                for value in values {
                    let name = required_text(value, "name")?.to_owned();
                    let component_state = value
                        .get("state")
                        .and_then(Value::as_str)
                        .map_or(HealthState::Unknown, HealthState::parse);
                    let desired_count = bounded_u32(value.get("replicas_desired"))?;
                    let ready_count = bounded_u32(value.get("replicas_ready"))?;
                    let mut status_counts = BTreeMap::new();
                    status_counts.insert(format!("{component_state:?}").to_ascii_uppercase(), 1);
                    components.push(HealthComponentProjection {
                        name,
                        state: component_state,
                        desired_count,
                        ready_count,
                        status_counts,
                    });
                }
            }
        }
        bound_components(&components)?;
        for component in &components {
            if !scope
                .components()
                .iter()
                .any(|selector| selector.name == component.name)
            {
                return Err(DigitalOceanAppDeploymentResultError::ComponentDrift);
            }
        }
        let projection = HealthProjection::new(state, components)?;
        let cost_receipt = CostReceipt::new(
            DigitalOceanAppsOperation::GetAppHealth.as_str(),
            response.response_bytes() as u64,
        )?;
        Ok(HealthRead {
            projection,
            response_digest: response.response_digest(),
            request_receipt: recorded.receipt(),
            cost_receipt,
        })
    }
}

impl Default for DigitalOceanAppsProvider<BlockedEnvTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvTransport).expect("blocked provider definition valid")
    }
}

fn parse_json(response: &DigitalOceanAppsResponse) -> Result<Value> {
    serde_json::from_slice(response.body())
        .map_err(|_| DigitalOceanAppDeploymentResultError::InvalidResponse)
}

fn nested_object<'a>(root: &'a Value, key: &str) -> Option<&'a Value> {
    root.get(key).filter(|value| value.is_object())
}

fn required_text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .ok_or(DigitalOceanAppDeploymentResultError::InvalidResponse)
}

fn validate_optional_identity(
    value: &Value,
    key: &str,
    expected: &str,
    error: DigitalOceanAppDeploymentResultError,
) -> Result<()> {
    if let Some(actual) = value.get(key).and_then(Value::as_str)
        && actual != expected
    {
        return Err(error);
    }
    Ok(())
}

fn parse_next_page(root: &Value) -> Result<Option<u32>> {
    if let Some(page) = root.get("next_page").and_then(Value::as_u64) {
        let page = u32::try_from(page)
            .map_err(|_| DigitalOceanAppDeploymentResultError::InvalidResponse)?;
        validate_page_number(page)?;
        return Ok(Some(page));
    }
    if let Some(next) = root
        .get("links")
        .and_then(|value| value.get("pages"))
        .and_then(|value| value.get("next"))
        .and_then(Value::as_str)
    {
        let query = next.split('?').nth(1).unwrap_or_default();
        for pair in query.split('&') {
            let mut parts = pair.splitn(2, '=');
            if parts.next() == Some("page") {
                let page = parts
                    .next()
                    .and_then(|value| value.parse::<u32>().ok())
                    .ok_or(DigitalOceanAppDeploymentResultError::InvalidResponse)?;
                validate_page_number(page)?;
                return Ok(Some(page));
            }
        }
        return Err(DigitalOceanAppDeploymentResultError::InvalidResponse);
    }
    Ok(None)
}

fn parse_time(value: Option<&Value>) -> Result<Option<DateTime<Utc>>> {
    let Some(value) = value.and_then(Value::as_str) else {
        return Ok(None);
    };
    DateTime::parse_from_rfc3339(value)
        .map(|time| Some(time.with_timezone(&Utc)))
        .map_err(|_| DigitalOceanAppDeploymentResultError::InvalidResponse)
}

fn optional_digest(value: Option<&Value>) -> Option<Digest> {
    value
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .map(|text| Digest::from_text(text.as_bytes()))
}

fn source_revision_digest(value: &Value) -> Option<Digest> {
    value
        .get("source_revision_digest")
        .and_then(Value::as_str)
        .and_then(|value| Digest::parse(value.to_owned()).ok())
        .or_else(|| {
            value
                .get("source_commit_hash")
                .and_then(Value::as_str)
                .map(|value| Digest::from_text(value.as_bytes()))
        })
        .or_else(|| {
            value
                .get("source_revision")
                .and_then(Value::as_str)
                .map(|value| Digest::from_text(value.as_bytes()))
        })
}

fn parse_deployment(value: &Value) -> Result<DeploymentProjection> {
    let id = required_text(value, "id")?;
    let deployment_digest = Digest::from_text(id.as_bytes());
    let phase = value
        .get("phase")
        .and_then(Value::as_str)
        .map_or(DeploymentPhase::Unknown, DeploymentPhase::parse);
    let cause_digest = optional_digest(value.get("cause"));
    let created_at = parse_time(value.get("created_at"))?;
    let updated_at = parse_time(value.get("updated_at"))?;
    let phase_last_updated_at = parse_time(value.get("phase_last_updated_at"))?;
    let superseded_by_digest = optional_digest(value.get("superseded_by"));
    let source_digest = source_revision_digest(value);
    let mut components = Vec::new();
    if let Some(values) = value.get("components").and_then(Value::as_array) {
        for item in values {
            components.push(parse_component(item, source_digest.clone())?);
        }
    }
    if let Some(progress) = value.get("progress") {
        walk_progress(progress, &mut components, source_digest.clone())?;
    }
    components.sort_by(|left, right| left.name.cmp(&right.name));
    if components
        .windows(2)
        .any(|pair| pair[0].name == pair[1].name)
    {
        return Err(DigitalOceanAppDeploymentResultError::ComponentDrift);
    }
    bound_components(&components)?;
    DeploymentProjection::new(
        deployment_digest,
        phase,
        cause_digest,
        created_at,
        updated_at,
        phase_last_updated_at,
        superseded_by_digest,
        source_digest,
        components,
    )
}

fn parse_component(value: &Value, source_digest: Option<Digest>) -> Result<ComponentProjection> {
    let name = value
        .get("name")
        .and_then(Value::as_str)
        .or_else(|| value.get("component_name").and_then(Value::as_str))
        .ok_or(DigitalOceanAppDeploymentResultError::InvalidResponse)?;
    let component_type = value
        .get("component_type")
        .and_then(Value::as_str)
        .or_else(|| value.get("type").and_then(Value::as_str))
        .unwrap_or("UNKNOWN");
    let status = value
        .get("status")
        .and_then(Value::as_str)
        .map_or(ComponentStatus::Unknown, ComponentStatus::parse);
    ComponentProjection::new(
        name,
        component_type,
        status,
        bounded_u32(
            value
                .get("replicas_desired")
                .or_else(|| value.get("desired_count")),
        )?,
        bounded_u32(
            value
                .get("replicas_ready")
                .or_else(|| value.get("ready_count")),
        )?,
        source_revision_digest(value).or(source_digest),
    )
}

fn walk_progress(
    value: &Value,
    components: &mut Vec<ComponentProjection>,
    source_digest: Option<Digest>,
) -> Result<()> {
    if let Some(object) = value.as_object() {
        if object.contains_key("component_name") {
            components.push(parse_component(value, source_digest.clone())?);
        }
        for child in object.values() {
            if child.is_object() || child.is_array() {
                walk_progress(child, components, source_digest.clone())?;
            }
        }
    } else if let Some(values) = value.as_array() {
        for child in values {
            walk_progress(child, components, source_digest.clone())?;
        }
    }
    Ok(())
}

fn parse_event(value: &Value) -> Result<EventProjection> {
    let event_id_digest = optional_digest(value.get("id"))
        .ok_or(DigitalOceanAppDeploymentResultError::InvalidResponse)?;
    let deployment_id_digest = optional_digest(value.get("deployment_id"))
        .ok_or(DigitalOceanAppDeploymentResultError::InvalidResponse)?;
    let event_type = required_text(value, "type")?;
    EventProjection::new(
        event_id_digest,
        deployment_id_digest,
        event_type,
        parse_time(value.get("created_at"))?,
    )
}

fn bounded_u32(value: Option<&Value>) -> Result<Option<u32>> {
    let Some(value) = value else { return Ok(None) };
    let Some(value) = value.as_u64() else {
        return Err(DigitalOceanAppDeploymentResultError::InvalidResponse);
    };
    Ok(Some(u32::try_from(value).map_err(|_| {
        DigitalOceanAppDeploymentResultError::InvalidResponse
    })?))
}

#[derive(Clone, Debug)]
pub struct RecordingTransport {
    app: VecDeque<std::result::Result<DigitalOceanAppsResponse, DigitalOceanTransportError>>,
    deployments:
        VecDeque<std::result::Result<DigitalOceanAppsResponse, DigitalOceanTransportError>>,
    deployment: VecDeque<std::result::Result<DigitalOceanAppsResponse, DigitalOceanTransportError>>,
    events: VecDeque<std::result::Result<DigitalOceanAppsResponse, DigitalOceanTransportError>>,
    health: VecDeque<std::result::Result<DigitalOceanAppsResponse, DigitalOceanTransportError>>,
    requests: Vec<RecordedRequest>,
    provenance: TransportProvenance,
}

impl RecordingTransport {
    #[must_use]
    pub fn new(provenance: TransportProvenance) -> Self {
        Self {
            app: VecDeque::new(),
            deployments: VecDeque::new(),
            deployment: VecDeque::new(),
            events: VecDeque::new(),
            health: VecDeque::new(),
            requests: Vec::new(),
            provenance,
        }
    }

    pub fn push_app_response(
        &mut self,
        response: std::result::Result<DigitalOceanAppsResponse, DigitalOceanTransportError>,
    ) {
        self.app.push_back(response);
    }
    pub fn push_deployments_response(
        &mut self,
        response: std::result::Result<DigitalOceanAppsResponse, DigitalOceanTransportError>,
    ) {
        self.deployments.push_back(response);
    }
    pub fn push_deployment_response(
        &mut self,
        response: std::result::Result<DigitalOceanAppsResponse, DigitalOceanTransportError>,
    ) {
        self.deployment.push_back(response);
    }
    pub fn push_events_response(
        &mut self,
        response: std::result::Result<DigitalOceanAppsResponse, DigitalOceanTransportError>,
    ) {
        self.events.push_back(response);
    }
    pub fn push_health_response(
        &mut self,
        response: std::result::Result<DigitalOceanAppsResponse, DigitalOceanTransportError>,
    ) {
        self.health.push_back(response);
    }
    #[must_use]
    pub fn requests(&self) -> &[RecordedRequest] {
        &self.requests
    }

    fn pop(
        queue: &mut VecDeque<
            std::result::Result<DigitalOceanAppsResponse, DigitalOceanTransportError>,
        >,
    ) -> std::result::Result<DigitalOceanAppsResponse, DigitalOceanTransportError> {
        queue
            .pop_front()
            .unwrap_or(Err(DigitalOceanTransportError::Unknown))
    }
}

impl Default for RecordingTransport {
    fn default() -> Self {
        Self::new(TransportProvenance::Recording)
    }
}

impl DigitalOceanAppsTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }
    fn get_app(
        &mut self,
        request: &GetAppRequest,
    ) -> std::result::Result<DigitalOceanAppsResponse, DigitalOceanTransportError> {
        self.requests.push(RecordedRequest {
            operation: DigitalOceanAppsOperation::GetApp,
            request_digest: request.request_digest.clone(),
            path_digest: request.scope_digest.clone(),
            scope_digest: request.scope_digest.clone(),
            page_digest: None,
        });
        Self::pop(&mut self.app)
    }
    fn list_deployments(
        &mut self,
        request: &ListDeploymentsRequest,
    ) -> std::result::Result<DigitalOceanAppsResponse, DigitalOceanTransportError> {
        self.requests.push(RecordedRequest {
            operation: DigitalOceanAppsOperation::ListDeployments,
            request_digest: request.request_digest.clone(),
            path_digest: request.scope_digest.clone(),
            scope_digest: request.scope_digest.clone(),
            page_digest: request
                .cursor
                .as_ref()
                .map(|cursor| cursor.page_digest().clone()),
        });
        Self::pop(&mut self.deployments)
    }
    fn get_deployment(
        &mut self,
        request: &GetDeploymentRequest,
    ) -> std::result::Result<DigitalOceanAppsResponse, DigitalOceanTransportError> {
        self.requests.push(RecordedRequest {
            operation: DigitalOceanAppsOperation::GetDeployment,
            request_digest: request.request_digest.clone(),
            path_digest: request.scope_digest.clone(),
            scope_digest: request.scope_digest.clone(),
            page_digest: None,
        });
        Self::pop(&mut self.deployment)
    }
    fn list_events(
        &mut self,
        request: &ListEventsRequest,
    ) -> std::result::Result<DigitalOceanAppsResponse, DigitalOceanTransportError> {
        self.requests.push(RecordedRequest {
            operation: DigitalOceanAppsOperation::ListEvents,
            request_digest: request.request_digest.clone(),
            path_digest: request.scope_digest.clone(),
            scope_digest: request.scope_digest.clone(),
            page_digest: request
                .cursor
                .as_ref()
                .map(|cursor| cursor.page_digest().clone()),
        });
        Self::pop(&mut self.events)
    }
    fn get_app_health(
        &mut self,
        request: &GetAppHealthRequest,
    ) -> std::result::Result<DigitalOceanAppsResponse, DigitalOceanTransportError> {
        self.requests.push(RecordedRequest {
            operation: DigitalOceanAppsOperation::GetAppHealth,
            request_digest: request.request_digest.clone(),
            path_digest: request.scope_digest.clone(),
            scope_digest: request.scope_digest.clone(),
            page_digest: None,
        });
        Self::pop(&mut self.health)
    }
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    responses: FixtureResponses,
    provenance: TransportProvenance,
}

#[derive(Clone, Debug)]
struct FixtureResponses {
    app: DigitalOceanAppsResponse,
    deployments: DigitalOceanAppsResponse,
    deployment: DigitalOceanAppsResponse,
    events: DigitalOceanAppsResponse,
    health: DigitalOceanAppsResponse,
}

impl FixtureTransport {
    #[must_use]
    pub fn for_scope(scope: &DigitalOceanAppDeploymentScope, observed_at: DateTime<Utc>) -> Self {
        Self::for_scope_with_provenance(scope, observed_at, TransportProvenance::Fixture)
    }

    #[must_use]
    pub fn for_scope_with_provenance(
        scope: &DigitalOceanAppDeploymentScope,
        observed_at: DateTime<Utc>,
        provenance: TransportProvenance,
    ) -> Self {
        let source_digest = scope.source_revision().digest().as_str();
        let first_component = &scope.components()[0];
        let components = scope
            .components()
            .iter()
            .map(|component| {
                json!({
                    "name": component.name,
                    "component_type": component.component_type,
                    "status": "READY",
                    "replicas_desired": 2,
                    "replicas_ready": 2,
                    "source_revision_digest": source_digest
                })
            })
            .collect::<Vec<_>>();
        let sensitive_spec = json!({
            "name": "private-app",
            "envs": [{"key": "TOKEN", "value": "fixture-secret"}],
            "domains": [{"domain": "private.example.com"}],
            "services": [{"name": first_component.name, "build_command": "make private", "github": {"repo": "https://github.com/private/repo"}}]
        });
        let deployment = json!({
            "id": scope.deployment().as_str(),
            "phase": "ACTIVE",
            "cause": "commit private-revision pushed from https://github.com/private/repo",
            "created_at": observed_at.to_rfc3339(),
            "updated_at": observed_at.to_rfc3339(),
            "phase_last_updated_at": observed_at.to_rfc3339(),
            "source_revision_digest": source_digest,
            "components": components
        });
        let event = json!({
            "id": "fixture-event-1",
            "deployment_id": scope.deployment().as_str(),
            "type": "DEPLOYMENT",
            "created_at": observed_at.to_rfc3339()
        });
        let health_components = scope
            .components()
            .iter()
            .map(|component| {
                json!({
                    "name": component.name,
                    "state": "HEALTHY",
                    "replicas_desired": 2,
                    "replicas_ready": 2,
                    "cpu_usage_percent": 99.0,
                    "memory_usage_percent": 99.0
                })
            })
            .collect::<Vec<_>>();
        let app = json!({
            "app": {
                "id": scope.app().as_str(),
                "account_id": scope.account().as_str(),
                "team_id": scope.team().as_str(),
                "region": scope.region().as_str(),
                "active_deployment": {"id": scope.deployment().as_str()},
                "spec": sensitive_spec
            }
        });
        let events = json!({"events": [event]});
        let health = json!({"app_health": {"state": "HEALTHY", "components": health_components}});
        let make_response = |value: &Value| DigitalOceanAppsResponse::json(200, value, provenance);
        Self {
            responses: FixtureResponses {
                app: make_response(&app),
                deployments: make_response(&json!({"deployments": [deployment.clone()]})),
                deployment: make_response(&json!({"deployment": deployment})),
                events: make_response(&events),
                health: make_response(&health),
            },
            provenance,
        }
    }
}

impl DigitalOceanAppsTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }
    fn get_app(
        &mut self,
        _request: &GetAppRequest,
    ) -> std::result::Result<DigitalOceanAppsResponse, DigitalOceanTransportError> {
        Ok(self.responses.app.clone())
    }
    fn list_deployments(
        &mut self,
        _request: &ListDeploymentsRequest,
    ) -> std::result::Result<DigitalOceanAppsResponse, DigitalOceanTransportError> {
        Ok(self.responses.deployments.clone())
    }
    fn get_deployment(
        &mut self,
        _request: &GetDeploymentRequest,
    ) -> std::result::Result<DigitalOceanAppsResponse, DigitalOceanTransportError> {
        Ok(self.responses.deployment.clone())
    }
    fn list_events(
        &mut self,
        _request: &ListEventsRequest,
    ) -> std::result::Result<DigitalOceanAppsResponse, DigitalOceanTransportError> {
        Ok(self.responses.events.clone())
    }
    fn get_app_health(
        &mut self,
        _request: &GetAppHealthRequest,
    ) -> std::result::Result<DigitalOceanAppsResponse, DigitalOceanTransportError> {
        Ok(self.responses.health.clone())
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    fixture: FixtureTransport,
}

impl LoopbackTransport {
    #[must_use]
    pub fn for_scope(scope: &DigitalOceanAppDeploymentScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            fixture: FixtureTransport::for_scope_with_provenance(
                scope,
                observed_at,
                TransportProvenance::Loopback,
            ),
        }
    }
}

impl DigitalOceanAppsTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }
    fn get_app(
        &mut self,
        request: &GetAppRequest,
    ) -> std::result::Result<DigitalOceanAppsResponse, DigitalOceanTransportError> {
        self.fixture.get_app(request)
    }
    fn list_deployments(
        &mut self,
        request: &ListDeploymentsRequest,
    ) -> std::result::Result<DigitalOceanAppsResponse, DigitalOceanTransportError> {
        self.fixture.list_deployments(request)
    }
    fn get_deployment(
        &mut self,
        request: &GetDeploymentRequest,
    ) -> std::result::Result<DigitalOceanAppsResponse, DigitalOceanTransportError> {
        self.fixture.get_deployment(request)
    }
    fn list_events(
        &mut self,
        request: &ListEventsRequest,
    ) -> std::result::Result<DigitalOceanAppsResponse, DigitalOceanTransportError> {
        self.fixture.list_events(request)
    }
    fn get_app_health(
        &mut self,
        request: &GetAppHealthRequest,
    ) -> std::result::Result<DigitalOceanAppsResponse, DigitalOceanTransportError> {
        self.fixture.get_app_health(request)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvTransport;

impl DigitalOceanAppsTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }
    fn get_app(
        &mut self,
        _request: &GetAppRequest,
    ) -> std::result::Result<DigitalOceanAppsResponse, DigitalOceanTransportError> {
        Err(DigitalOceanTransportError::BlockedEnv)
    }
    fn list_deployments(
        &mut self,
        _request: &ListDeploymentsRequest,
    ) -> std::result::Result<DigitalOceanAppsResponse, DigitalOceanTransportError> {
        Err(DigitalOceanTransportError::BlockedEnv)
    }
    fn get_deployment(
        &mut self,
        _request: &GetDeploymentRequest,
    ) -> std::result::Result<DigitalOceanAppsResponse, DigitalOceanTransportError> {
        Err(DigitalOceanTransportError::BlockedEnv)
    }
    fn list_events(
        &mut self,
        _request: &ListEventsRequest,
    ) -> std::result::Result<DigitalOceanAppsResponse, DigitalOceanTransportError> {
        Err(DigitalOceanTransportError::BlockedEnv)
    }
    fn get_app_health(
        &mut self,
        _request: &GetAppHealthRequest,
    ) -> std::result::Result<DigitalOceanAppsResponse, DigitalOceanTransportError> {
        Err(DigitalOceanTransportError::BlockedEnv)
    }
}

fn response_for_status(status: u16) -> std::result::Result<(), DigitalOceanTransportError> {
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(match status {
            400 => DigitalOceanTransportError::BadRequest,
            401 => DigitalOceanTransportError::Unauthorized,
            403 => DigitalOceanTransportError::Forbidden,
            404 => DigitalOceanTransportError::NotFound,
            409 => DigitalOceanTransportError::Conflict,
            429 => DigitalOceanTransportError::RateLimited {
                retry_after_seconds: None,
            },
            500..=599 => DigitalOceanTransportError::ServerError { status },
            _ => DigitalOceanTransportError::Unknown,
        })
    }
}
