use std::{collections::VecDeque, fmt};

use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::error::{AzureEventHubPostureResultError, AzureEventHubTransportError, Result};
use crate::model::{
    AzureEventHubPostureScope, ConsumerGroupPostureProjection, CostReceipt, Digest,
    EventHubPostureProjection, NamespacePostureProjection, RequestReceipt, TransportProvenance,
    validate_page_number, validate_page_size, validate_response_bytes,
};
use crate::{
    API_REVISION, ARM_API_VERSION, CONTRACT_VERSION, LAYER1_PERMISSIONS, MAX_IDENTIFIER_BYTES,
    MAX_PAGES, MAX_RESPONSE_BYTES, PROVIDER_ID,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum AzureEventHubOperation {
    GetNamespace,
    GetEventHub,
    GetConsumerGroup,
    ListConsumerGroups,
}

impl AzureEventHubOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GetNamespace => "GetNamespace",
            Self::GetEventHub => "GetEventHub",
            Self::GetConsumerGroup => "GetConsumerGroup",
            Self::ListConsumerGroups => "ListConsumerGroups",
        }
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Cursor {
    continuation_digest: Digest,
    scope_digest: Digest,
    page_number: u16,
}

pub type ConsumerGroupCursor = Cursor;

impl Cursor {
    pub fn new(
        opaque_next_link: impl Into<String>,
        scope: &AzureEventHubPostureScope,
        page_number: u16,
    ) -> Result<Self> {
        let next_link = opaque_next_link.into();
        if next_link.is_empty() || next_link.len() > MAX_IDENTIFIER_BYTES || page_number < 2 {
            return Err(AzureEventHubPostureResultError::InvalidRequest);
        }
        let cursor = Self {
            continuation_digest: Digest::from_parts(
                "azure-event-hub-opaque-next-link/v1",
                &[
                    ("next_link", next_link),
                    ("scope", scope.digest().as_str().to_owned()),
                    ("page", page_number.to_string()),
                ],
            ),
            scope_digest: scope.digest(),
            page_number,
        };
        cursor.validate(scope)?;
        Ok(cursor)
    }

    pub fn continuation_digest(&self) -> &Digest {
        &self.continuation_digest
    }

    pub fn marker_digest(&self) -> &Digest {
        &self.continuation_digest
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    fn validate(&self, scope: &AzureEventHubPostureScope) -> Result<()> {
        validate_page_number(self.page_number)?;
        if self.scope_digest != scope.digest() {
            return Err(AzureEventHubPostureResultError::ScopeMismatch);
        }
        self.continuation_digest.validate()
    }
}

impl fmt::Debug for Cursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Cursor")
            .field("continuation_digest", &self.continuation_digest)
            .field("scope_digest", &self.scope_digest)
            .field("page_number", &self.page_number)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub operation: AzureEventHubOperation,
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub path_digest: Digest,
    pub query_digest: Digest,
    pub cursor_digest: Option<Digest>,
    pub redacted: bool,
}

impl RecordedRequest {
    pub fn receipt(&self, response_bytes: u64) -> Result<RequestReceipt> {
        RequestReceipt::new(
            self.operation.as_str(),
            self.request_digest.clone(),
            self.path_digest.clone(),
            self.query_digest.clone(),
            self.scope_digest.clone(),
            response_bytes,
        )
    }

    fn validate(&self) -> Result<()> {
        if !self.redacted {
            return Err(AzureEventHubPostureResultError::TamperedEvidence);
        }
        self.scope_digest.validate()?;
        self.request_digest.validate()?;
        self.path_digest.validate()?;
        self.query_digest.validate()?;
        self.cursor_digest
            .as_ref()
            .map(Digest::validate)
            .transpose()
            .map(|_| ())
    }
}

fn redacted_namespace_path(scope: &AzureEventHubPostureScope) -> String {
    format!(
        "/subscriptions/{}/resourceGroups/{}/providers/Microsoft.EventHub/namespaces/{}",
        &scope.subscription_digest().as_str()[..16],
        &scope.resource_group_digest().as_str()[..16],
        &scope.namespace_digest().as_str()[..16]
    )
}

fn redacted_event_hub_path(scope: &AzureEventHubPostureScope) -> String {
    format!(
        "{}/eventhubs/{}",
        redacted_namespace_path(scope),
        &scope.event_hub_digest().as_str()[..16],
    )
}

fn redacted_consumer_group_path(scope: &AzureEventHubPostureScope) -> String {
    format!(
        "{}/consumergroups/{}",
        redacted_event_hub_path(scope),
        &scope.consumer_group_digest().as_str()[..16]
    )
}

fn request_digest(
    domain: &str,
    scope: &AzureEventHubPostureScope,
    cursor: Option<&Cursor>,
) -> Digest {
    Digest::from_parts(
        domain,
        &[
            ("scope", scope.digest().as_str().to_owned()),
            (
                "cursor",
                cursor.map_or_else(String::new, |value| {
                    value.continuation_digest().as_str().to_owned()
                }),
            ),
            ("api", scope.api_revision().to_owned()),
        ],
    )
}

#[derive(Clone, Eq, PartialEq)]
pub struct GetNamespaceRequest {
    scope: AzureEventHubPostureScope,
    request_digest: Digest,
}

impl GetNamespaceRequest {
    pub fn for_scope(scope: &AzureEventHubPostureScope) -> Result<Self> {
        scope.validate()?;
        Ok(Self {
            scope: scope.clone(),
            request_digest: request_digest("azure-event-hub-get-namespace-request/v1", scope, None),
        })
    }

    pub fn scope(&self) -> &AzureEventHubPostureScope {
        &self.scope
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "{}?api-version={}",
            redacted_namespace_path(&self.scope),
            ARM_API_VERSION
        )
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        let path = self.path_and_query();
        RecordedRequest {
            operation: AzureEventHubOperation::GetNamespace,
            scope_digest: self.scope.digest(),
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(path.as_bytes()),
            query_digest: Digest::from_parts(
                "azure-event-hub-query/v1",
                &[("api", ARM_API_VERSION.to_owned())],
            ),
            cursor_digest: None,
            redacted: true,
        }
    }
}

impl fmt::Debug for GetNamespaceRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GetNamespaceRequest")
            .field("scope_digest", &self.scope.digest())
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GetEventHubRequest {
    scope: AzureEventHubPostureScope,
    request_digest: Digest,
}

impl GetEventHubRequest {
    pub fn for_scope(scope: &AzureEventHubPostureScope) -> Result<Self> {
        scope.validate()?;
        Ok(Self {
            scope: scope.clone(),
            request_digest: request_digest("azure-event-hub-get-event-hub-request/v1", scope, None),
        })
    }

    pub fn scope(&self) -> &AzureEventHubPostureScope {
        &self.scope
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "{}?api-version={}",
            redacted_event_hub_path(&self.scope),
            ARM_API_VERSION
        )
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        let path = self.path_and_query();
        RecordedRequest {
            operation: AzureEventHubOperation::GetEventHub,
            scope_digest: self.scope.digest(),
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(path.as_bytes()),
            query_digest: Digest::from_parts(
                "azure-event-hub-query/v1",
                &[("api", ARM_API_VERSION.to_owned())],
            ),
            cursor_digest: None,
            redacted: true,
        }
    }
}

impl fmt::Debug for GetEventHubRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GetEventHubRequest")
            .field("scope_digest", &self.scope.digest())
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct GetConsumerGroupRequest {
    scope: AzureEventHubPostureScope,
    request_digest: Digest,
}

impl GetConsumerGroupRequest {
    pub fn for_scope(scope: &AzureEventHubPostureScope) -> Result<Self> {
        scope.validate()?;
        Ok(Self {
            scope: scope.clone(),
            request_digest: request_digest(
                "azure-event-hub-get-consumer-group-request/v1",
                scope,
                None,
            ),
        })
    }

    pub fn scope(&self) -> &AzureEventHubPostureScope {
        &self.scope
    }

    pub fn request_digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn path_and_query(&self) -> String {
        format!(
            "{}?api-version={}",
            redacted_consumer_group_path(&self.scope),
            ARM_API_VERSION
        )
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        let path = self.path_and_query();
        RecordedRequest {
            operation: AzureEventHubOperation::GetConsumerGroup,
            scope_digest: self.scope.digest(),
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(path.as_bytes()),
            query_digest: Digest::from_parts(
                "azure-event-hub-query/v1",
                &[("api", ARM_API_VERSION.to_owned())],
            ),
            cursor_digest: None,
            redacted: true,
        }
    }
}

impl fmt::Debug for GetConsumerGroupRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GetConsumerGroupRequest")
            .field("scope_digest", &self.scope.digest())
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ListConsumerGroupsRequest {
    scope: AzureEventHubPostureScope,
    page_size: u16,
    page_number: u16,
    cursor: Option<Cursor>,
    request_digest: Digest,
}

impl ListConsumerGroupsRequest {
    pub fn new(
        scope: &AzureEventHubPostureScope,
        page_size: u16,
        cursor: Option<Cursor>,
    ) -> Result<Self> {
        scope.validate()?;
        validate_page_size(page_size)?;
        let page_number = cursor.as_ref().map_or(1, Cursor::page_number);
        if let Some(cursor) = cursor.as_ref() {
            cursor.validate(scope)?;
        }
        let request_digest = request_digest(
            "azure-event-hub-list-consumer-groups-request/v1",
            scope,
            cursor.as_ref(),
        );
        Ok(Self {
            scope: scope.clone(),
            page_size,
            page_number,
            cursor,
            request_digest,
        })
    }

    pub fn first(scope: &AzureEventHubPostureScope, page_size: u16) -> Result<Self> {
        Self::new(scope, page_size, None)
    }

    pub fn scope(&self) -> &AzureEventHubPostureScope {
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
            "{}/consumergroups?api-version={}&$top={}&$skiptoken={}",
            redacted_event_hub_path(&self.scope),
            ARM_API_VERSION,
            self.page_size,
            self.cursor
                .as_ref()
                .map_or_else(String::new, |cursor| cursor.continuation_digest().as_str()
                    [..16]
                    .to_owned())
        )
    }

    pub fn recorded_request(&self) -> RecordedRequest {
        let path = self.path_and_query();
        RecordedRequest {
            operation: AzureEventHubOperation::ListConsumerGroups,
            scope_digest: self.scope.digest(),
            request_digest: self.request_digest.clone(),
            path_digest: Digest::from_text(path.as_bytes()),
            query_digest: Digest::from_parts(
                "azure-event-hub-query/v1",
                &[
                    ("api", ARM_API_VERSION.to_owned()),
                    ("top", self.page_size.to_string()),
                    (
                        "cursor",
                        self.cursor.as_ref().map_or_else(String::new, |cursor| {
                            cursor.continuation_digest().as_str().to_owned()
                        }),
                    ),
                ],
            ),
            cursor_digest: self
                .cursor
                .as_ref()
                .map(|cursor| cursor.continuation_digest().clone()),
            redacted: true,
        }
    }
}

impl fmt::Debug for ListConsumerGroupsRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ListConsumerGroupsRequest")
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
pub struct GetNamespaceResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub namespace: NamespacePostureProjection,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub request_receipt: RequestReceipt,
    pub cost_receipt: CostReceipt,
}

impl GetNamespaceResponse {
    pub fn new(
        request: &GetNamespaceRequest,
        namespace: NamespacePostureProjection,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        namespace.validate_integrity()?;
        if namespace.namespace_identity_digest != request.scope().namespace_digest() {
            return Err(AzureEventHubPostureResultError::ScopeMismatch);
        }
        let recorded = request.recorded_request();
        recorded.validate()?;
        let mut response = Self {
            scope_digest: request.scope().digest(),
            request_digest: request.request_digest().clone(),
            namespace,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-azure-event-hub-namespace-response"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            request_receipt: recorded.receipt(response_bytes)?,
            cost_receipt: CostReceipt::new(
                AzureEventHubOperation::GetNamespace.as_str(),
                response_bytes,
            )?,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    pub fn with_declared_digest(mut self, evidence_digest: Digest) -> Self {
        self.evidence_digest = evidence_digest;
        self
    }

    pub fn validate_integrity(&self, request: &GetNamespaceRequest) -> Result<()> {
        validate_response_bytes(self.response_bytes)?;
        if self.scope_digest != request.scope().digest()
            || self.request_digest != *request.request_digest()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.provenance.is_connected()
            || self.provenance.is_first_party()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AzureEventHubPostureResultError::TamperedEvidence);
        }
        self.request_receipt.validate_integrity()?;
        self.cost_receipt.validate_integrity()?;
        self.namespace.validate_integrity()?;
        if self.namespace.namespace_identity_digest != request.scope().namespace_digest() {
            return Err(AzureEventHubPostureResultError::ScopeMismatch);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "azure-event-hub-get-namespace-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                (
                    "namespace",
                    self.namespace.projection_digest.as_str().to_owned(),
                ),
                ("bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
                (
                    "request_receipt",
                    self.request_receipt.receipt_digest.as_str().to_owned(),
                ),
                (
                    "cost_receipt",
                    self.cost_receipt.receipt_digest.as_str().to_owned(),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetEventHubResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub event_hub: EventHubPostureProjection,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub request_receipt: RequestReceipt,
    pub cost_receipt: CostReceipt,
}

impl GetEventHubResponse {
    pub fn new(
        request: &GetEventHubRequest,
        event_hub: EventHubPostureProjection,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        event_hub.validate_integrity()?;
        if event_hub.event_hub_identity_digest != request.scope().event_hub_digest() {
            return Err(AzureEventHubPostureResultError::ScopeMismatch);
        }
        let recorded = request.recorded_request();
        recorded.validate()?;
        let mut response = Self {
            scope_digest: request.scope().digest(),
            request_digest: request.request_digest().clone(),
            event_hub,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-azure-event-hub-event-hub-response"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            request_receipt: recorded.receipt(response_bytes)?,
            cost_receipt: CostReceipt::new(
                AzureEventHubOperation::GetEventHub.as_str(),
                response_bytes,
            )?,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    pub fn with_declared_digest(mut self, evidence_digest: Digest) -> Self {
        self.evidence_digest = evidence_digest;
        self
    }

    pub fn validate_integrity(&self, request: &GetEventHubRequest) -> Result<()> {
        validate_response_bytes(self.response_bytes)?;
        if self.scope_digest != request.scope().digest()
            || self.request_digest != *request.request_digest()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.provenance.is_connected()
            || self.provenance.is_first_party()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AzureEventHubPostureResultError::TamperedEvidence);
        }
        self.request_receipt.validate_integrity()?;
        self.cost_receipt.validate_integrity()?;
        self.event_hub.validate_integrity()?;
        if self.event_hub.event_hub_identity_digest != request.scope().event_hub_digest() {
            return Err(AzureEventHubPostureResultError::ScopeMismatch);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "azure-event-hub-get-event-hub-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                (
                    "event_hub",
                    self.event_hub.projection_digest.as_str().to_owned(),
                ),
                ("bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
                (
                    "request_receipt",
                    self.request_receipt.receipt_digest.as_str().to_owned(),
                ),
                (
                    "cost_receipt",
                    self.cost_receipt.receipt_digest.as_str().to_owned(),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetConsumerGroupResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub consumer_group: ConsumerGroupPostureProjection,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub request_receipt: RequestReceipt,
    pub cost_receipt: CostReceipt,
}

impl GetConsumerGroupResponse {
    pub fn new(
        request: &GetConsumerGroupRequest,
        consumer_group: ConsumerGroupPostureProjection,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        consumer_group.validate_integrity()?;
        if consumer_group.consumer_group_identity_digest != request.scope().consumer_group_digest()
        {
            return Err(AzureEventHubPostureResultError::ScopeMismatch);
        }
        let recorded = request.recorded_request();
        recorded.validate()?;
        let mut response = Self {
            scope_digest: request.scope().digest(),
            request_digest: request.request_digest().clone(),
            consumer_group,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-azure-event-hub-consumer-group-response"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            request_receipt: recorded.receipt(response_bytes)?,
            cost_receipt: CostReceipt::new(
                AzureEventHubOperation::GetConsumerGroup.as_str(),
                response_bytes,
            )?,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    pub fn with_declared_digest(mut self, evidence_digest: Digest) -> Self {
        self.evidence_digest = evidence_digest;
        self
    }

    pub fn validate_integrity(&self, request: &GetConsumerGroupRequest) -> Result<()> {
        validate_response_bytes(self.response_bytes)?;
        if self.scope_digest != request.scope().digest()
            || self.request_digest != *request.request_digest()
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.provenance.is_connected()
            || self.provenance.is_first_party()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AzureEventHubPostureResultError::TamperedEvidence);
        }
        self.request_receipt.validate_integrity()?;
        self.cost_receipt.validate_integrity()?;
        self.consumer_group.validate_integrity()?;
        if self.consumer_group.consumer_group_identity_digest
            != request.scope().consumer_group_digest()
        {
            return Err(AzureEventHubPostureResultError::ScopeMismatch);
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "azure-event-hub-get-consumer-group-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                (
                    "consumer_group",
                    self.consumer_group.projection_digest.as_str().to_owned(),
                ),
                ("bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
                (
                    "request_receipt",
                    self.request_receipt.receipt_digest.as_str().to_owned(),
                ),
                (
                    "cost_receipt",
                    self.cost_receipt.receipt_digest.as_str().to_owned(),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListConsumerGroupsResponse {
    pub scope_digest: Digest,
    pub request_digest: Digest,
    pub page_number: u16,
    pub consumer_groups: Vec<ConsumerGroupPostureProjection>,
    pub next_cursor: Option<Cursor>,
    pub response_bytes: u64,
    pub provenance: TransportProvenance,
    pub evidence_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
    pub provider_receipt: bool,
    pub request_receipt: RequestReceipt,
    pub cost_receipt: CostReceipt,
}

impl ListConsumerGroupsResponse {
    pub fn new(
        request: &ListConsumerGroupsRequest,
        consumer_groups: Vec<ConsumerGroupPostureProjection>,
        next_cursor: Option<Cursor>,
        response_bytes: u64,
        provenance: TransportProvenance,
    ) -> Result<Self> {
        validate_response_bytes(response_bytes)?;
        if consumer_groups.len() > request.page_size() as usize {
            return Err(AzureEventHubPostureResultError::PartialEvidence);
        }
        if let Some(cursor) = next_cursor.as_ref() {
            cursor.validate(request.scope())?;
            if cursor.page_number() != request.page_number().saturating_add(1)
                || request.cursor().is_some_and(|previous| {
                    previous.continuation_digest() == cursor.continuation_digest()
                })
            {
                return Err(AzureEventHubPostureResultError::PaginationLoop);
            }
        }
        for consumer_group in &consumer_groups {
            consumer_group.validate_integrity()?;
        }
        let recorded = request.recorded_request();
        recorded.validate()?;
        let mut response = Self {
            scope_digest: request.scope().digest(),
            request_digest: request.request_digest().clone(),
            page_number: request.page_number(),
            consumer_groups,
            next_cursor,
            response_bytes,
            provenance,
            evidence_digest: Digest::from_text("unsealed-azure-event-hub-list-response"),
            connected: false,
            native: false,
            first_party: false,
            provider_receipt: false,
            request_receipt: recorded.receipt(response_bytes)?,
            cost_receipt: CostReceipt::new(
                AzureEventHubOperation::ListConsumerGroups.as_str(),
                response_bytes,
            )?,
        };
        response.evidence_digest = response.calculate_digest();
        Ok(response)
    }

    pub fn with_declared_digest(mut self, evidence_digest: Digest) -> Self {
        self.evidence_digest = evidence_digest;
        self
    }

    pub fn has_more(&self) -> bool {
        self.next_cursor.is_some()
    }

    pub fn validate_integrity(&self, request: &ListConsumerGroupsRequest) -> Result<()> {
        validate_response_bytes(self.response_bytes)?;
        if self.scope_digest != request.scope().digest()
            || self.request_digest != *request.request_digest()
            || self.page_number != request.page_number()
            || self.consumer_groups.len() > request.page_size() as usize
            || self.connected
            || self.native
            || self.first_party
            || self.provider_receipt
            || self.provenance.is_native()
            || self.provenance.is_connected()
            || self.provenance.is_first_party()
            || self.evidence_digest != self.calculate_digest()
        {
            return Err(AzureEventHubPostureResultError::TamperedEvidence);
        }
        self.request_receipt.validate_integrity()?;
        self.cost_receipt.validate_integrity()?;
        for consumer_group in &self.consumer_groups {
            consumer_group.validate_integrity()?;
        }
        if let Some(cursor) = self.next_cursor.as_ref() {
            cursor.validate(request.scope())?;
            if cursor.page_number() != request.page_number().saturating_add(1) {
                return Err(AzureEventHubPostureResultError::PaginationLoop);
            }
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Digest {
        Digest::from_parts(
            "azure-event-hub-list-consumer-groups-response/v1",
            &[
                ("scope", self.scope_digest.as_str().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                ("page", self.page_number.to_string()),
                (
                    "consumer_groups",
                    crate::model::join_digests(
                        self.consumer_groups
                            .iter()
                            .map(|value| value.projection_digest.clone()),
                    ),
                ),
                (
                    "cursor",
                    self.next_cursor
                        .as_ref()
                        .map_or_else(String::new, |cursor| {
                            cursor.continuation_digest().as_str().to_owned()
                        }),
                ),
                ("bytes", self.response_bytes.to_string()),
                ("provenance", self.provenance.as_str().to_owned()),
                (
                    "request_receipt",
                    self.request_receipt.receipt_digest.as_str().to_owned(),
                ),
                (
                    "cost_receipt",
                    self.cost_receipt.receipt_digest.as_str().to_owned(),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug)]
pub struct AzureEventHubsProviderDefinition {
    pub provider_id: String,
    pub provider_revision: u64,
    pub api_revision: String,
    pub contract_version: String,
    pub release: String,
    pub capability_digest: Digest,
    pub provider_digest: Digest,
    pub connected: bool,
    pub native: bool,
    pub first_party: bool,
}

impl AzureEventHubsProviderDefinition {
    pub fn new(provider_revision: u64, release: impl Into<String>) -> Result<Self> {
        let release = release.into();
        if provider_revision == 0 || release.is_empty() || release.len() > 128 {
            return Err(AzureEventHubPostureResultError::ProviderDrift);
        }
        let capability_digest = Digest::from_parts(
            "azure-event-hub-provider-capabilities/v1",
            &LAYER1_PERMISSIONS
                .iter()
                .map(|permission| ("permission", (*permission).to_owned()))
                .collect::<Vec<_>>(),
        );
        let provider_digest = Digest::from_parts(
            "azure-event-hub-provider/v1",
            &[
                ("provider_id", PROVIDER_ID.to_owned()),
                ("provider_revision", provider_revision.to_string()),
                ("api_revision", API_REVISION.to_owned()),
                ("contract_version", CONTRACT_VERSION.to_owned()),
                ("release", release.clone()),
                ("capability", capability_digest.as_str().to_owned()),
            ],
        );
        Ok(Self {
            provider_id: PROVIDER_ID.to_owned(),
            provider_revision,
            api_revision: API_REVISION.to_owned(),
            contract_version: CONTRACT_VERSION.to_owned(),
            release,
            capability_digest,
            provider_digest,
            connected: false,
            native: false,
            first_party: false,
        })
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
            || self.provider_digest
                != Self::new(self.provider_revision, self.release.clone())?.provider_digest
        {
            Err(AzureEventHubPostureResultError::ProviderDrift)
        } else {
            Ok(())
        }
    }
}

impl Serialize for AzureEventHubsProviderDefinition {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("AzureEventHubsProviderDefinition", 10)?;
        state.serialize_field("providerId", &self.provider_id)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("apiRevision", &self.api_revision)?;
        state.serialize_field("contractVersion", &self.contract_version)?;
        state.serialize_field("release", &self.release)?;
        state.serialize_field("capabilityDigest", &self.capability_digest)?;
        state.serialize_field("providerDigest", &self.provider_digest)?;
        state.serialize_field("connected", &self.connected)?;
        state.serialize_field("native", &self.native)?;
        state.serialize_field("firstParty", &self.first_party)?;
        state.end()
    }
}

pub type AzureEventHubProviderDefinition = AzureEventHubsProviderDefinition;

pub trait AzureEventHubsTransport: fmt::Debug {
    fn provenance(&self) -> TransportProvenance;

    fn get_namespace(
        &mut self,
        request: &GetNamespaceRequest,
    ) -> std::result::Result<GetNamespaceResponse, AzureEventHubTransportError>;

    fn get_event_hub(
        &mut self,
        request: &GetEventHubRequest,
    ) -> std::result::Result<GetEventHubResponse, AzureEventHubTransportError>;

    fn get_consumer_group(
        &mut self,
        request: &GetConsumerGroupRequest,
    ) -> std::result::Result<GetConsumerGroupResponse, AzureEventHubTransportError>;

    fn list_consumer_groups(
        &mut self,
        request: &ListConsumerGroupsRequest,
    ) -> std::result::Result<ListConsumerGroupsResponse, AzureEventHubTransportError>;
}

pub struct AzureEventHubsProvider<T> {
    transport: T,
    definition: AzureEventHubsProviderDefinition,
}

impl<T: AzureEventHubsTransport> fmt::Debug for AzureEventHubsProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AzureEventHubsProvider")
            .field("definition", &self.definition)
            .field("transport_provenance", &self.transport.provenance())
            .finish()
    }
}

impl<T: AzureEventHubsTransport> AzureEventHubsProvider<T> {
    pub fn new(transport: T) -> Result<Self> {
        Self::with_identity(transport, 1, "layer1-recording")
    }

    pub fn with_identity(
        transport: T,
        provider_revision: u64,
        release: impl Into<String>,
    ) -> Result<Self> {
        let definition = AzureEventHubsProviderDefinition::new(provider_revision, release)?;
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn definition(&self) -> &AzureEventHubsProviderDefinition {
        &self.definition
    }

    pub fn provenance(&self) -> TransportProvenance {
        self.transport.provenance()
    }

    pub fn get_namespace(
        &mut self,
        request: &GetNamespaceRequest,
    ) -> std::result::Result<GetNamespaceResponse, AzureEventHubTransportError> {
        let response = self.transport.get_namespace(request)?;
        validate_response(
            response.validate_integrity(request),
            response.provenance,
            self.provenance(),
            response.connected,
            response.native,
            response.first_party,
            response.provider_receipt,
        )?;
        Ok(response)
    }

    pub fn get_event_hub(
        &mut self,
        request: &GetEventHubRequest,
    ) -> std::result::Result<GetEventHubResponse, AzureEventHubTransportError> {
        let response = self.transport.get_event_hub(request)?;
        validate_response(
            response.validate_integrity(request),
            response.provenance,
            self.provenance(),
            response.connected,
            response.native,
            response.first_party,
            response.provider_receipt,
        )?;
        Ok(response)
    }

    pub fn get_consumer_group(
        &mut self,
        request: &GetConsumerGroupRequest,
    ) -> std::result::Result<GetConsumerGroupResponse, AzureEventHubTransportError> {
        let response = self.transport.get_consumer_group(request)?;
        validate_response(
            response.validate_integrity(request),
            response.provenance,
            self.provenance(),
            response.connected,
            response.native,
            response.first_party,
            response.provider_receipt,
        )?;
        Ok(response)
    }

    pub fn list_consumer_groups(
        &mut self,
        request: &ListConsumerGroupsRequest,
    ) -> std::result::Result<ListConsumerGroupsResponse, AzureEventHubTransportError> {
        let response = self.transport.list_consumer_groups(request)?;
        validate_response(
            response.validate_integrity(request),
            response.provenance,
            self.provenance(),
            response.connected,
            response.native,
            response.first_party,
            response.provider_receipt,
        )?;
        Ok(response)
    }

    pub fn into_transport(self) -> T {
        self.transport
    }
}

fn validate_response(
    validation: Result<()>,
    response_provenance: TransportProvenance,
    expected_provenance: TransportProvenance,
    connected: bool,
    native: bool,
    first_party: bool,
    provider_receipt: bool,
) -> std::result::Result<(), AzureEventHubTransportError> {
    match validation {
        Ok(()) => {}
        Err(AzureEventHubPostureResultError::TamperedEvidence) => {
            return Err(AzureEventHubTransportError::Tampered);
        }
        Err(AzureEventHubPostureResultError::PaginationLoop) => {
            return Err(AzureEventHubTransportError::PaginationLoop);
        }
        Err(AzureEventHubPostureResultError::ApiDrift) => {
            return Err(AzureEventHubTransportError::ApiDrift);
        }
        Err(AzureEventHubPostureResultError::ScopeMismatch) => {
            return Err(AzureEventHubTransportError::ScopeDrift);
        }
        Err(AzureEventHubPostureResultError::StaleState) => {
            return Err(AzureEventHubTransportError::StaleState);
        }
        Err(AzureEventHubPostureResultError::PartialEvidence) => {
            return Err(AzureEventHubTransportError::Partial);
        }
        Err(_) => return Err(AzureEventHubTransportError::InvalidResponse),
    }
    if response_provenance != expected_provenance
        || connected
        || native
        || first_party
        || provider_receipt
        || response_provenance.is_native()
        || response_provenance.is_connected()
        || response_provenance.is_first_party()
    {
        return Err(AzureEventHubTransportError::InvalidResponse);
    }
    Ok(())
}

impl Default for AzureEventHubsProvider<BlockedEnvTransport> {
    fn default() -> Self {
        Self::new(BlockedEnvTransport).expect("blocked Azure Event Hub provider definition")
    }
}

impl<T: AzureEventHubsTransport> AzureEventHubsProvider<T> {
    pub fn from_registration(
        registration: &crate::service::AzureEventHubPostureRegistration,
        transport: T,
    ) -> Result<Self> {
        let provider = Self::with_identity(
            transport,
            registration.provider_revision(),
            registration.provider_release().to_owned(),
        )?;
        if provider.definition.provider_digest != *registration.provider_digest() {
            return Err(AzureEventHubPostureResultError::ProviderDrift);
        }
        Ok(provider)
    }
}

#[derive(Clone, Debug)]
pub struct RecordingTransport {
    provenance: TransportProvenance,
    namespace_responses:
        VecDeque<std::result::Result<GetNamespaceResponse, AzureEventHubTransportError>>,
    event_hub_responses:
        VecDeque<std::result::Result<GetEventHubResponse, AzureEventHubTransportError>>,
    consumer_group_responses:
        VecDeque<std::result::Result<GetConsumerGroupResponse, AzureEventHubTransportError>>,
    list_responses:
        VecDeque<std::result::Result<ListConsumerGroupsResponse, AzureEventHubTransportError>>,
    requests: Vec<RecordedRequest>,
}

impl RecordingTransport {
    pub fn new(provenance: TransportProvenance) -> Self {
        Self {
            provenance,
            namespace_responses: VecDeque::new(),
            event_hub_responses: VecDeque::new(),
            consumer_group_responses: VecDeque::new(),
            list_responses: VecDeque::new(),
            requests: Vec::new(),
        }
    }

    pub fn push_namespace_response(
        &mut self,
        response: std::result::Result<GetNamespaceResponse, AzureEventHubTransportError>,
    ) {
        self.namespace_responses.push_back(response);
    }

    pub fn push_event_hub_response(
        &mut self,
        response: std::result::Result<GetEventHubResponse, AzureEventHubTransportError>,
    ) {
        self.event_hub_responses.push_back(response);
    }

    pub fn push_consumer_group_response(
        &mut self,
        response: std::result::Result<GetConsumerGroupResponse, AzureEventHubTransportError>,
    ) {
        self.consumer_group_responses.push_back(response);
    }

    pub fn push_list_response(
        &mut self,
        response: std::result::Result<ListConsumerGroupsResponse, AzureEventHubTransportError>,
    ) {
        self.list_responses.push_back(response);
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

impl AzureEventHubsTransport for RecordingTransport {
    fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    fn get_namespace(
        &mut self,
        request: &GetNamespaceRequest,
    ) -> std::result::Result<GetNamespaceResponse, AzureEventHubTransportError> {
        self.requests.push(request.recorded_request());
        self.namespace_responses
            .pop_front()
            .unwrap_or(Err(AzureEventHubTransportError::InvalidResponse))
    }

    fn get_event_hub(
        &mut self,
        request: &GetEventHubRequest,
    ) -> std::result::Result<GetEventHubResponse, AzureEventHubTransportError> {
        self.requests.push(request.recorded_request());
        self.event_hub_responses
            .pop_front()
            .unwrap_or(Err(AzureEventHubTransportError::InvalidResponse))
    }

    fn get_consumer_group(
        &mut self,
        request: &GetConsumerGroupRequest,
    ) -> std::result::Result<GetConsumerGroupResponse, AzureEventHubTransportError> {
        self.requests.push(request.recorded_request());
        self.consumer_group_responses
            .pop_front()
            .unwrap_or(Err(AzureEventHubTransportError::InvalidResponse))
    }

    fn list_consumer_groups(
        &mut self,
        request: &ListConsumerGroupsRequest,
    ) -> std::result::Result<ListConsumerGroupsResponse, AzureEventHubTransportError> {
        self.requests.push(request.recorded_request());
        self.list_responses
            .pop_front()
            .unwrap_or(Err(AzureEventHubTransportError::InvalidResponse))
    }
}

#[derive(Clone, Debug)]
pub struct FixtureTransport {
    scope: AzureEventHubPostureScope,
    observed_at: DateTime<Utc>,
}

impl FixtureTransport {
    pub fn for_scope(scope: &AzureEventHubPostureScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            scope: scope.clone(),
            observed_at,
        }
    }

    fn namespace(&self) -> Result<NamespacePostureProjection> {
        NamespacePostureProjection::new(
            self.scope.namespace_digest(),
            "Active",
            "Succeeded",
            "Standard",
            1,
            Some(format!(
                "https://{}.servicebus.windows.net/",
                self.scope.namespace().as_str()
            )),
            Some("fixture-user-metadata".to_owned()),
            format!("fixture-namespace-{}", self.observed_at.timestamp()),
        )
    }

    fn event_hub(&self) -> Result<EventHubPostureProjection> {
        EventHubPostureProjection::new(
            self.scope.event_hub_digest(),
            "Active",
            2,
            vec!["0".to_owned(), "1".to_owned()],
            7,
            false,
            None,
            Some("fixture-user-metadata".to_owned()),
            format!("fixture-event-hub-{}", self.observed_at.timestamp()),
        )
    }

    fn consumer_group(&self) -> Result<ConsumerGroupPostureProjection> {
        ConsumerGroupPostureProjection::for_scope(
            &self.scope,
            "Active",
            Some("fixture-user-metadata".to_owned()),
            format!("fixture-consumer-group-{}", self.observed_at.timestamp()),
        )
    }

    fn namespace_response(
        &self,
        request: &GetNamespaceRequest,
        provenance: TransportProvenance,
    ) -> std::result::Result<GetNamespaceResponse, AzureEventHubTransportError> {
        GetNamespaceResponse::new(
            request,
            self.namespace()
                .map_err(|_| AzureEventHubTransportError::InvalidResponse)?,
            1_024,
            provenance,
        )
        .map_err(|_| AzureEventHubTransportError::InvalidResponse)
    }

    fn event_hub_response(
        &self,
        request: &GetEventHubRequest,
        provenance: TransportProvenance,
    ) -> std::result::Result<GetEventHubResponse, AzureEventHubTransportError> {
        GetEventHubResponse::new(
            request,
            self.event_hub()
                .map_err(|_| AzureEventHubTransportError::InvalidResponse)?,
            1_024,
            provenance,
        )
        .map_err(|_| AzureEventHubTransportError::InvalidResponse)
    }

    fn consumer_group_response(
        &self,
        request: &GetConsumerGroupRequest,
        provenance: TransportProvenance,
    ) -> std::result::Result<GetConsumerGroupResponse, AzureEventHubTransportError> {
        GetConsumerGroupResponse::new(
            request,
            self.consumer_group()
                .map_err(|_| AzureEventHubTransportError::InvalidResponse)?,
            1_024,
            provenance,
        )
        .map_err(|_| AzureEventHubTransportError::InvalidResponse)
    }

    fn list_response(
        &self,
        request: &ListConsumerGroupsRequest,
        provenance: TransportProvenance,
    ) -> std::result::Result<ListConsumerGroupsResponse, AzureEventHubTransportError> {
        ListConsumerGroupsResponse::new(
            request,
            vec![
                self.consumer_group()
                    .map_err(|_| AzureEventHubTransportError::InvalidResponse)?,
            ],
            None,
            1_024,
            provenance,
        )
        .map_err(|_| AzureEventHubTransportError::InvalidResponse)
    }
}

impl AzureEventHubsTransport for FixtureTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fixture
    }

    fn get_namespace(
        &mut self,
        request: &GetNamespaceRequest,
    ) -> std::result::Result<GetNamespaceResponse, AzureEventHubTransportError> {
        self.namespace_response(request, TransportProvenance::Fixture)
    }

    fn get_event_hub(
        &mut self,
        request: &GetEventHubRequest,
    ) -> std::result::Result<GetEventHubResponse, AzureEventHubTransportError> {
        self.event_hub_response(request, TransportProvenance::Fixture)
    }

    fn get_consumer_group(
        &mut self,
        request: &GetConsumerGroupRequest,
    ) -> std::result::Result<GetConsumerGroupResponse, AzureEventHubTransportError> {
        self.consumer_group_response(request, TransportProvenance::Fixture)
    }

    fn list_consumer_groups(
        &mut self,
        request: &ListConsumerGroupsRequest,
    ) -> std::result::Result<ListConsumerGroupsResponse, AzureEventHubTransportError> {
        self.list_response(request, TransportProvenance::Fixture)
    }
}

#[derive(Clone, Debug)]
pub struct LoopbackTransport {
    inner: FixtureTransport,
}

impl LoopbackTransport {
    pub fn for_scope(scope: &AzureEventHubPostureScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            inner: FixtureTransport::for_scope(scope, observed_at),
        }
    }
}

impl AzureEventHubsTransport for LoopbackTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Loopback
    }

    fn get_namespace(
        &mut self,
        request: &GetNamespaceRequest,
    ) -> std::result::Result<GetNamespaceResponse, AzureEventHubTransportError> {
        self.inner
            .namespace_response(request, TransportProvenance::Loopback)
    }

    fn get_event_hub(
        &mut self,
        request: &GetEventHubRequest,
    ) -> std::result::Result<GetEventHubResponse, AzureEventHubTransportError> {
        self.inner
            .event_hub_response(request, TransportProvenance::Loopback)
    }

    fn get_consumer_group(
        &mut self,
        request: &GetConsumerGroupRequest,
    ) -> std::result::Result<GetConsumerGroupResponse, AzureEventHubTransportError> {
        self.inner
            .consumer_group_response(request, TransportProvenance::Loopback)
    }

    fn list_consumer_groups(
        &mut self,
        request: &ListConsumerGroupsRequest,
    ) -> std::result::Result<ListConsumerGroupsResponse, AzureEventHubTransportError> {
        self.inner
            .list_response(request, TransportProvenance::Loopback)
    }
}

#[derive(Clone, Debug)]
pub struct FakeTransport {
    inner: FixtureTransport,
}

impl FakeTransport {
    pub fn for_scope(scope: &AzureEventHubPostureScope, observed_at: DateTime<Utc>) -> Self {
        Self {
            inner: FixtureTransport::for_scope(scope, observed_at),
        }
    }
}

impl AzureEventHubsTransport for FakeTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::Fake
    }

    fn get_namespace(
        &mut self,
        request: &GetNamespaceRequest,
    ) -> std::result::Result<GetNamespaceResponse, AzureEventHubTransportError> {
        self.inner
            .namespace_response(request, TransportProvenance::Fake)
    }

    fn get_event_hub(
        &mut self,
        request: &GetEventHubRequest,
    ) -> std::result::Result<GetEventHubResponse, AzureEventHubTransportError> {
        self.inner
            .event_hub_response(request, TransportProvenance::Fake)
    }

    fn get_consumer_group(
        &mut self,
        request: &GetConsumerGroupRequest,
    ) -> std::result::Result<GetConsumerGroupResponse, AzureEventHubTransportError> {
        self.inner
            .consumer_group_response(request, TransportProvenance::Fake)
    }

    fn list_consumer_groups(
        &mut self,
        request: &ListConsumerGroupsRequest,
    ) -> std::result::Result<ListConsumerGroupsResponse, AzureEventHubTransportError> {
        self.inner.list_response(request, TransportProvenance::Fake)
    }
}

#[derive(Clone, Debug, Default)]
pub struct BlockedEnvTransport;

impl AzureEventHubsTransport for BlockedEnvTransport {
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::BlockedEnv
    }

    fn get_namespace(
        &mut self,
        _request: &GetNamespaceRequest,
    ) -> std::result::Result<GetNamespaceResponse, AzureEventHubTransportError> {
        Err(AzureEventHubTransportError::BlockedEnv)
    }

    fn get_event_hub(
        &mut self,
        _request: &GetEventHubRequest,
    ) -> std::result::Result<GetEventHubResponse, AzureEventHubTransportError> {
        Err(AzureEventHubTransportError::BlockedEnv)
    }

    fn get_consumer_group(
        &mut self,
        _request: &GetConsumerGroupRequest,
    ) -> std::result::Result<GetConsumerGroupResponse, AzureEventHubTransportError> {
        Err(AzureEventHubTransportError::BlockedEnv)
    }

    fn list_consumer_groups(
        &mut self,
        _request: &ListConsumerGroupsRequest,
    ) -> std::result::Result<ListConsumerGroupsResponse, AzureEventHubTransportError> {
        Err(AzureEventHubTransportError::BlockedEnv)
    }
}

pub const MAX_PROVIDER_RESPONSE_BYTES: u64 = MAX_RESPONSE_BYTES;
pub const MAX_PROVIDER_PAGES: u16 = MAX_PAGES;
