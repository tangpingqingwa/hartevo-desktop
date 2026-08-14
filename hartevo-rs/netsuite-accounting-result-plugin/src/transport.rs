//! Bounded SuiteTalk GET-shaped transport and deterministic provenance seams.

use std::{collections::VecDeque, fmt};

use crate::model::{
    AccountId, CollectionFilter, DataCenter, Digest, MissionId, ModelError, NetSuiteBounds,
    NetSuiteCollectionSummary, NetSuitePayload, NetSuiteReadOperation, NetSuiteRecordMetadata,
    NetSuiteRecordType, NetSuiteScope, NetSuiteSelectedRecordSummary, ObservationWindow, ProjectId,
    RecordId, Revision, RoleId, SecretReference, WorkProductId, digest_serializable,
};
use serde::{Deserialize, Serialize, Serializer};

pub(crate) const MAX_CURSOR_BYTES: usize = 4 * 1024;

/// Cursor values are retained only by a transport and cross public boundaries
/// as their digest.
#[derive(Clone, Eq, PartialEq)]
pub struct OpaqueCursor {
    digest: Digest,
}

impl OpaqueCursor {
    pub fn new(value: impl Into<String>) -> Result<Self, ModelError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_CURSOR_BYTES {
            return Err(ModelError::InvalidBounds);
        }
        Ok(Self {
            digest: Digest::from_text(value),
        })
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }
}

impl fmt::Debug for OpaqueCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueCursor")
            .field("digest", &self.digest)
            .finish()
    }
}

impl Serialize for OpaqueCursor {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.digest.as_str())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum NetSuiteSuiteTalkEndpoint {
    RecordMetadata {
        record_type: NetSuiteRecordType,
    },
    RecordCollection {
        record_type: NetSuiteRecordType,
    },
    SelectedRecord {
        record_type: NetSuiteRecordType,
        record_id: RecordId,
    },
}

impl NetSuiteSuiteTalkEndpoint {
    pub fn path(&self) -> String {
        match self {
            Self::RecordMetadata { .. } => "/services/rest/record/v1/metadata-catalog".to_owned(),
            Self::RecordCollection { record_type } => {
                format!("/services/rest/record/v1/{}", record_type.as_str())
            }
            Self::SelectedRecord {
                record_type,
                record_id,
            } => format!(
                "/services/rest/record/v1/{}/{}",
                record_type.as_str(),
                record_id.as_str()
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum NetSuiteHttpMethod {
    Get,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetSuiteGetRequest {
    operation: NetSuiteReadOperation,
    endpoint: NetSuiteSuiteTalkEndpoint,
    method: NetSuiteHttpMethod,
    account_id: AccountId,
    data_center: DataCenter,
    role_id: RoleId,
    record_type: NetSuiteRecordType,
    record_id: Option<RecordId>,
    collection_filter: CollectionFilter,
    scope_digest: Digest,
    permission_digest: Digest,
    consent_digest: Digest,
    project_id: ProjectId,
    project_revision: Revision,
    mission_id: MissionId,
    mission_revision: Revision,
    work_product_id: WorkProductId,
    work_product_revision: Revision,
    credential_revision: Revision,
    page_number: u16,
    page_size: u16,
    cursor: Option<OpaqueCursor>,
    window: ObservationWindow,
    secret_reference_digest: Digest,
}

impl NetSuiteGetRequest {
    pub fn new(
        scope: &NetSuiteScope,
        secret_reference: &SecretReference,
        operation: NetSuiteReadOperation,
        bounds: NetSuiteBounds,
        window: ObservationWindow,
        page_number: u16,
        cursor: Option<OpaqueCursor>,
    ) -> Result<Self, ModelError> {
        if !operation.is_get()
            || page_number == 0
            || page_number > bounds.max_pages()
            || window != *scope.observation_window()
            || secret_reference.scope_digest() != &scope.digest()
            || secret_reference.is_revoked()
        {
            return Err(ModelError::InvalidScope);
        }
        let record_id = scope.record_id().cloned();
        if matches!(operation, NetSuiteReadOperation::SelectedRecord) && record_id.is_none() {
            return Err(ModelError::InvalidScope);
        }
        let endpoint = match operation {
            NetSuiteReadOperation::RecordMetadata => NetSuiteSuiteTalkEndpoint::RecordMetadata {
                record_type: scope.record_type(),
            },
            NetSuiteReadOperation::RecordCollectionFilter => {
                NetSuiteSuiteTalkEndpoint::RecordCollection {
                    record_type: scope.record_type(),
                }
            }
            NetSuiteReadOperation::SelectedRecord => NetSuiteSuiteTalkEndpoint::SelectedRecord {
                record_type: scope.record_type(),
                record_id: record_id.clone().ok_or(ModelError::InvalidScope)?,
            },
            NetSuiteReadOperation::SuiteQlProposal => return Err(ModelError::InvalidSuiteQl),
        };
        Ok(Self {
            operation,
            endpoint,
            method: NetSuiteHttpMethod::Get,
            account_id: scope.account_id().clone(),
            data_center: scope.data_center().clone(),
            role_id: scope.role_id().clone(),
            record_type: scope.record_type(),
            record_id,
            collection_filter: scope.collection_filter().clone(),
            scope_digest: scope.digest(),
            permission_digest: scope.permission_digest().clone(),
            consent_digest: scope.consent_scope().digest().clone(),
            project_id: scope.project_id().clone(),
            project_revision: scope.project_revision(),
            mission_id: scope.mission_id().clone(),
            mission_revision: scope.mission_revision(),
            work_product_id: scope.work_product_id().clone(),
            work_product_revision: scope.work_product_revision(),
            credential_revision: secret_reference.credential_revision(),
            page_number,
            page_size: bounds.page_size(),
            cursor,
            window,
            secret_reference_digest: secret_reference.reference_digest().clone(),
        })
    }

    pub const fn operation(&self) -> NetSuiteReadOperation {
        self.operation
    }

    pub fn endpoint(&self) -> &NetSuiteSuiteTalkEndpoint {
        &self.endpoint
    }

    pub const fn method(&self) -> NetSuiteHttpMethod {
        self.method
    }

    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    pub fn data_center(&self) -> &DataCenter {
        &self.data_center
    }

    pub fn role_id(&self) -> &RoleId {
        &self.role_id
    }

    pub const fn record_type(&self) -> NetSuiteRecordType {
        self.record_type
    }

    pub fn record_id(&self) -> Option<&RecordId> {
        self.record_id.as_ref()
    }

    pub fn collection_filter(&self) -> &CollectionFilter {
        &self.collection_filter
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn consent_digest(&self) -> &Digest {
        &self.consent_digest
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub const fn project_revision(&self) -> Revision {
        self.project_revision
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub const fn mission_revision(&self) -> Revision {
        self.mission_revision
    }

    pub fn work_product_id(&self) -> &WorkProductId {
        &self.work_product_id
    }

    pub const fn work_product_revision(&self) -> Revision {
        self.work_product_revision
    }

    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    pub const fn page_number(&self) -> u16 {
        self.page_number
    }

    pub const fn page_size(&self) -> u16 {
        self.page_size
    }

    pub fn cursor(&self) -> Option<&OpaqueCursor> {
        self.cursor.as_ref()
    }

    pub fn window(&self) -> &ObservationWindow {
        &self.window
    }

    pub fn secret_reference_digest(&self) -> &Digest {
        &self.secret_reference_digest
    }

    pub fn request_digest(&self) -> Result<Digest, ModelError> {
        digest_serializable(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetSuiteGetResponse {
    operation: NetSuiteReadOperation,
    endpoint: NetSuiteSuiteTalkEndpoint,
    payload: NetSuitePayload,
    scope_digest: Digest,
    permission_digest: Digest,
    consent_digest: Digest,
    project_id: ProjectId,
    project_revision: Revision,
    mission_id: MissionId,
    mission_revision: Revision,
    work_product_id: WorkProductId,
    work_product_revision: Revision,
    credential_revision: Revision,
    status: u16,
    response_size: usize,
    provider_revision: String,
    next_cursor: Option<OpaqueCursor>,
    response_digest: Digest,
}

impl NetSuiteGetResponse {
    pub fn new(
        request: &NetSuiteGetRequest,
        payload: NetSuitePayload,
        provider_revision: impl Into<String>,
        status: u16,
        next_cursor: Option<OpaqueCursor>,
    ) -> Result<Self, NetSuiteTransportError> {
        let provider_revision = provider_revision.into();
        if provider_revision.is_empty() {
            return Err(NetSuiteTransportError::invalid_response(
                "empty provider revision",
            ));
        }
        let response_size = serde_json::to_vec(&payload)
            .map_err(|error| NetSuiteTransportError::invalid_response(error.to_string()))?
            .len();
        let mut response = Self {
            operation: request.operation(),
            endpoint: request.endpoint().clone(),
            payload,
            scope_digest: request.scope_digest().clone(),
            permission_digest: request.permission_digest().clone(),
            consent_digest: request.consent_digest().clone(),
            project_id: request.project_id().clone(),
            project_revision: request.project_revision(),
            mission_id: request.mission_id().clone(),
            mission_revision: request.mission_revision(),
            work_product_id: request.work_product_id().clone(),
            work_product_revision: request.work_product_revision(),
            credential_revision: request.credential_revision(),
            status,
            response_size,
            provider_revision,
            next_cursor,
            response_digest: Digest::from_text("uninitialized-netsuite-response"),
        };
        response.response_digest = response.recompute_digest()?;
        Ok(response)
    }

    pub const fn operation(&self) -> NetSuiteReadOperation {
        self.operation
    }

    pub fn endpoint(&self) -> &NetSuiteSuiteTalkEndpoint {
        &self.endpoint
    }

    pub fn payload(&self) -> &NetSuitePayload {
        &self.payload
    }

    pub fn scope_digest(&self) -> &Digest {
        &self.scope_digest
    }

    pub fn permission_digest(&self) -> &Digest {
        &self.permission_digest
    }

    pub fn consent_digest(&self) -> &Digest {
        &self.consent_digest
    }

    pub fn project_id(&self) -> &ProjectId {
        &self.project_id
    }

    pub const fn project_revision(&self) -> Revision {
        self.project_revision
    }

    pub fn mission_id(&self) -> &MissionId {
        &self.mission_id
    }

    pub const fn mission_revision(&self) -> Revision {
        self.mission_revision
    }

    pub fn work_product_id(&self) -> &WorkProductId {
        &self.work_product_id
    }

    pub const fn work_product_revision(&self) -> Revision {
        self.work_product_revision
    }

    pub const fn credential_revision(&self) -> Revision {
        self.credential_revision
    }

    pub const fn status(&self) -> u16 {
        self.status
    }

    pub const fn response_size(&self) -> usize {
        self.response_size
    }

    pub fn provider_revision(&self) -> &str {
        &self.provider_revision
    }

    pub fn next_cursor(&self) -> Option<&OpaqueCursor> {
        self.next_cursor.as_ref()
    }

    pub fn response_digest(&self) -> &Digest {
        &self.response_digest
    }

    fn recompute_digest(&self) -> Result<Digest, NetSuiteTransportError> {
        let material = NetSuiteGetResponseMaterial {
            operation: self.operation,
            endpoint: self.endpoint.clone(),
            payload: self.payload.clone(),
            scope_digest: self.scope_digest.clone(),
            permission_digest: self.permission_digest.clone(),
            consent_digest: self.consent_digest.clone(),
            project_id: self.project_id.clone(),
            project_revision: self.project_revision,
            mission_id: self.mission_id.clone(),
            mission_revision: self.mission_revision,
            work_product_id: self.work_product_id.clone(),
            work_product_revision: self.work_product_revision,
            credential_revision: self.credential_revision,
            status: self.status,
            response_size: self.response_size,
            provider_revision: self.provider_revision.clone(),
            next_cursor_digest: self
                .next_cursor
                .as_ref()
                .map(|cursor| cursor.digest().clone()),
        };
        digest_serializable(&material)
            .map_err(|error| NetSuiteTransportError::invalid_response(error.to_string()))
    }

    pub fn validate_integrity(&self) -> Result<(), NetSuiteTransportError> {
        if self.response_digest != self.recompute_digest()? {
            return Err(NetSuiteTransportError::invalid_response(
                "response digest mismatch",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NetSuiteGetResponseMaterial {
    operation: NetSuiteReadOperation,
    endpoint: NetSuiteSuiteTalkEndpoint,
    payload: NetSuitePayload,
    scope_digest: Digest,
    permission_digest: Digest,
    consent_digest: Digest,
    project_id: ProjectId,
    project_revision: Revision,
    mission_id: MissionId,
    mission_revision: Revision,
    work_product_id: WorkProductId,
    work_product_revision: Revision,
    credential_revision: Revision,
    status: u16,
    response_size: usize,
    provider_revision: String,
    next_cursor_digest: Option<Digest>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetSuiteSnapshot {
    scope_digest: Digest,
    permission_digest: Digest,
    consent_digest: Digest,
    project_id: ProjectId,
    project_revision: Revision,
    mission_id: MissionId,
    mission_revision: Revision,
    work_product_id: WorkProductId,
    work_product_revision: Revision,
    credential_revision: Revision,
    provider_revision: String,
    metadata: Option<NetSuiteRecordMetadata>,
    collection_pages: Vec<NetSuiteCollectionSummary>,
    collection_cursors: Vec<Option<OpaqueCursor>>,
    selected_record: Option<NetSuiteSelectedRecordSummary>,
}

impl NetSuiteSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: &NetSuiteScope,
        secret_reference: &SecretReference,
        provider_revision: impl Into<String>,
        metadata: Option<NetSuiteRecordMetadata>,
        collection_pages: Vec<NetSuiteCollectionSummary>,
        collection_cursors: Vec<Option<OpaqueCursor>>,
        selected_record: Option<NetSuiteSelectedRecordSummary>,
    ) -> Result<Self, NetSuiteTransportError> {
        let provider_revision = provider_revision.into();
        if provider_revision.is_empty() || collection_pages.len() != collection_cursors.len() {
            return Err(NetSuiteTransportError::invalid_response(
                "invalid fixture snapshot",
            ));
        }
        Ok(Self {
            scope_digest: scope.digest(),
            permission_digest: scope.permission_digest().clone(),
            consent_digest: scope.consent_scope().digest().clone(),
            project_id: scope.project_id().clone(),
            project_revision: scope.project_revision(),
            mission_id: scope.mission_id().clone(),
            mission_revision: scope.mission_revision(),
            work_product_id: scope.work_product_id().clone(),
            work_product_revision: scope.work_product_revision(),
            credential_revision: secret_reference.credential_revision(),
            provider_revision,
            metadata,
            collection_pages,
            collection_cursors,
            selected_record,
        })
    }

    pub fn response_for(
        &self,
        request: &NetSuiteGetRequest,
    ) -> Result<NetSuiteGetResponse, NetSuiteTransportError> {
        if request.scope_digest() != &self.scope_digest
            || request.permission_digest() != &self.permission_digest
            || request.consent_digest() != &self.consent_digest
            || request.project_id() != &self.project_id
            || request.project_revision() != self.project_revision
            || request.mission_id() != &self.mission_id
            || request.mission_revision() != self.mission_revision
            || request.work_product_id() != &self.work_product_id
            || request.work_product_revision() != self.work_product_revision
            || request.credential_revision() != self.credential_revision
        {
            return Err(NetSuiteTransportError::scope_mismatch(
                "fixture response fence differs",
            ));
        }
        let (payload, next_cursor) = match request.operation() {
            NetSuiteReadOperation::RecordMetadata => (
                self.metadata
                    .clone()
                    .map(NetSuitePayload::RecordMetadata)
                    .ok_or_else(|| NetSuiteTransportError::not_found("record metadata"))?,
                None,
            ),
            NetSuiteReadOperation::RecordCollectionFilter => {
                let index = usize::from(request.page_number() - 1);
                let summary =
                    self.collection_pages.get(index).cloned().ok_or_else(|| {
                        NetSuiteTransportError::not_found("record collection page")
                    })?;
                (
                    NetSuitePayload::RecordCollection(summary),
                    self.collection_cursors[index].clone(),
                )
            }
            NetSuiteReadOperation::SelectedRecord => (
                self.selected_record
                    .clone()
                    .map(NetSuitePayload::SelectedRecord)
                    .ok_or_else(|| NetSuiteTransportError::not_found("selected record"))?,
                None,
            ),
            NetSuiteReadOperation::SuiteQlProposal => {
                return Err(NetSuiteTransportError::invalid_response(
                    "SuiteQL proposals never use a GET transport",
                ));
            }
        };
        NetSuiteGetResponse::new(
            request,
            payload,
            self.provider_revision.clone(),
            200,
            next_cursor,
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetSuiteTransportErrorKind {
    BlockedEnv,
    RateLimited,
    Timeout,
    ServerFailure,
    PermissionDenied,
    NotFound,
    InvalidResponse,
    ScopeMismatch,
}

impl NetSuiteTransportErrorKind {
    pub const fn retryable(self) -> bool {
        matches!(
            self,
            Self::RateLimited | Self::Timeout | Self::ServerFailure
        )
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct NetSuiteTransportError {
    kind: NetSuiteTransportErrorKind,
    status_code: Option<u16>,
    diagnostic_digest: Digest,
}

impl fmt::Debug for NetSuiteTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NetSuiteTransportError")
            .field("kind", &self.kind)
            .field("status_code", &self.status_code)
            .field("diagnostic_digest", &self.diagnostic_digest)
            .finish()
    }
}

impl fmt::Display for NetSuiteTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "NetSuite transport returned {:?}", self.kind)
    }
}

impl std::error::Error for NetSuiteTransportError {}

impl NetSuiteTransportError {
    pub fn new(
        kind: NetSuiteTransportErrorKind,
        status_code: Option<u16>,
        diagnostic: impl AsRef<[u8]>,
    ) -> Self {
        Self {
            kind,
            status_code,
            diagnostic_digest: Digest::from_bytes(diagnostic.as_ref()),
        }
    }

    pub fn blocked_env() -> Self {
        Self::new(NetSuiteTransportErrorKind::BlockedEnv, None, "BLOCKED_ENV")
    }

    pub fn rate_limited() -> Self {
        Self::new(
            NetSuiteTransportErrorKind::RateLimited,
            Some(429),
            "rate_limited",
        )
    }

    pub fn timeout() -> Self {
        Self::new(NetSuiteTransportErrorKind::Timeout, None, "timeout")
    }

    pub fn invalid_response(diagnostic: impl AsRef<[u8]>) -> Self {
        Self::new(
            NetSuiteTransportErrorKind::InvalidResponse,
            None,
            diagnostic,
        )
    }

    fn not_found(resource: &str) -> Self {
        Self::new(NetSuiteTransportErrorKind::NotFound, Some(404), resource)
    }

    fn scope_mismatch(diagnostic: impl AsRef<[u8]>) -> Self {
        Self::new(NetSuiteTransportErrorKind::ScopeMismatch, None, diagnostic)
    }

    pub const fn kind(&self) -> NetSuiteTransportErrorKind {
        self.kind
    }

    pub const fn status_code(&self) -> Option<u16> {
        self.status_code
    }

    pub fn diagnostic_digest(&self) -> &Digest {
        &self.diagnostic_digest
    }

    pub const fn is_retryable(&self) -> bool {
        self.kind.retryable()
    }
}

pub trait NetSuiteTransport: fmt::Debug {
    fn execute(
        &mut self,
        request: &NetSuiteGetRequest,
    ) -> Result<NetSuiteGetResponse, NetSuiteTransportError>;
}

#[derive(Clone, Debug)]
pub struct FixtureNetSuiteTransport {
    snapshot: NetSuiteSnapshot,
}

impl FixtureNetSuiteTransport {
    pub fn new(snapshot: NetSuiteSnapshot) -> Self {
        Self { snapshot }
    }
}

impl NetSuiteTransport for FixtureNetSuiteTransport {
    fn execute(
        &mut self,
        request: &NetSuiteGetRequest,
    ) -> Result<NetSuiteGetResponse, NetSuiteTransportError> {
        self.snapshot.response_for(request)
    }
}

pub type NetSuiteFixtureTransport = FixtureNetSuiteTransport;

#[derive(Clone, Debug)]
pub struct LoopbackNetSuiteTransport {
    snapshot: NetSuiteSnapshot,
}

impl LoopbackNetSuiteTransport {
    pub fn new(snapshot: NetSuiteSnapshot) -> Self {
        Self { snapshot }
    }
}

impl NetSuiteTransport for LoopbackNetSuiteTransport {
    fn execute(
        &mut self,
        request: &NetSuiteGetRequest,
    ) -> Result<NetSuiteGetResponse, NetSuiteTransportError> {
        self.snapshot.response_for(request)
    }
}

pub type NetSuiteLoopbackTransport = LoopbackNetSuiteTransport;

#[derive(Clone, Debug, Default)]
pub struct RecordingNetSuiteTransport {
    queue: VecDeque<Result<NetSuiteGetResponse, NetSuiteTransportError>>,
    requests: Vec<NetSuiteGetRequest>,
}

impl RecordingNetSuiteTransport {
    pub fn push_response(&mut self, response: NetSuiteGetResponse) {
        self.queue.push_back(Ok(response));
    }

    pub fn push_error(&mut self, error: NetSuiteTransportError) {
        self.queue.push_back(Err(error));
    }

    pub fn requests(&self) -> &[NetSuiteGetRequest] {
        &self.requests
    }
}

impl NetSuiteTransport for RecordingNetSuiteTransport {
    fn execute(
        &mut self,
        request: &NetSuiteGetRequest,
    ) -> Result<NetSuiteGetResponse, NetSuiteTransportError> {
        self.requests.push(request.clone());
        self.queue.pop_front().unwrap_or_else(|| {
            Err(NetSuiteTransportError::invalid_response(
                "recording transport queue exhausted",
            ))
        })
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvNetSuiteTransport;

impl NetSuiteTransport for BlockedEnvNetSuiteTransport {
    fn execute(
        &mut self,
        _request: &NetSuiteGetRequest,
    ) -> Result<NetSuiteGetResponse, NetSuiteTransportError> {
        Err(NetSuiteTransportError::blocked_env())
    }
}

pub type NetSuiteBlockedEnvTransport = BlockedEnvNetSuiteTransport;
