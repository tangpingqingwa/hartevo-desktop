//! Bounded SuiteTalk GET-shaped transport and deterministic provenance seams.

use std::{collections::VecDeque, fmt};

use crate::model::{
    AccountId, CollectionFilter, DataCenter, Digest, MissionId, ModelError, NetSuiteBounds,
    NetSuiteCollectionSummary, NetSuitePayload, NetSuiteReadOperation, NetSuiteRecordMetadata,
    NetSuiteRecordType, NetSuiteScope, NetSuiteSelectedRecordSummary, ObservationWindow, ProjectId,
    RecordId, Revision, RoleId, SecretReference, WorkProductId, digest_serializable,
};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};

pub(crate) const MAX_CURSOR_BYTES: usize = 4 * 1024;
pub(crate) const MAX_PROVIDER_REVISION_BYTES: usize = 64;

mod sealed {
    pub trait NetSuiteTransportSealed {}
}

fn valid_provider_revision(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PROVIDER_REVISION_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

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

#[derive(Clone, Eq, PartialEq)]
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
    fn redacted_identity(&self) -> (&'static str, NetSuiteRecordType, Option<Digest>, Digest) {
        let (kind, record_type, record_id_digest) = match self {
            Self::RecordMetadata { record_type } => ("record_metadata", *record_type, None),
            Self::RecordCollection { record_type } => ("record_collection", *record_type, None),
            Self::SelectedRecord {
                record_type,
                record_id,
            } => (
                "selected_record",
                *record_type,
                Some(Digest::from_text(record_id.as_str())),
            ),
        };
        (
            kind,
            record_type,
            record_id_digest,
            Digest::from_text(self.path()),
        )
    }

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

impl fmt::Debug for NetSuiteSuiteTalkEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (kind, record_type, record_id_digest, endpoint_digest) = self.redacted_identity();
        formatter
            .debug_struct("NetSuiteSuiteTalkEndpoint")
            .field("kind", &kind)
            .field("record_type", &record_type)
            .field("record_id_digest", &record_id_digest)
            .field("endpoint_digest", &endpoint_digest)
            .finish()
    }
}

impl Serialize for NetSuiteSuiteTalkEndpoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let (kind, record_type, record_id_digest, endpoint_digest) = self.redacted_identity();
        let mut state = serializer.serialize_struct("NetSuiteSuiteTalkEndpoint", 4)?;
        state.serialize_field("kind", kind)?;
        state.serialize_field("recordType", &record_type)?;
        state.serialize_field("recordIdDigest", &record_id_digest)?;
        state.serialize_field("endpointDigest", &endpoint_digest)?;
        state.end()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum NetSuiteHttpMethod {
    Get,
}

#[derive(Clone, Eq, PartialEq)]
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

impl fmt::Debug for NetSuiteGetRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let account_id_digest = Digest::from_text(self.account_id.as_str());
        let data_center_digest = Digest::from_text(self.data_center.as_str());
        let role_id_digest = Digest::from_text(self.role_id.as_str());
        let record_id_digest = self
            .record_id
            .as_ref()
            .map(|record_id| Digest::from_text(record_id.as_str()));
        let project_id_digest = Digest::from_text(self.project_id.as_str());
        let mission_id_digest = Digest::from_text(self.mission_id.as_str());
        let work_product_id_digest = Digest::from_text(self.work_product_id.as_str());
        formatter
            .debug_struct("NetSuiteGetRequest")
            .field("operation", &self.operation)
            .field("endpoint", &self.endpoint)
            .field("method", &self.method)
            .field("account_id_digest", &account_id_digest)
            .field("data_center_digest", &data_center_digest)
            .field("role_id_digest", &role_id_digest)
            .field("record_type", &self.record_type)
            .field("record_id_digest", &record_id_digest)
            .field("collection_filter_digest", &self.collection_filter.digest())
            .field("scope_digest", &self.scope_digest)
            .field("permission_digest", &self.permission_digest)
            .field("consent_digest", &self.consent_digest)
            .field("project_id_digest", &project_id_digest)
            .field("project_revision", &self.project_revision)
            .field("mission_id_digest", &mission_id_digest)
            .field("mission_revision", &self.mission_revision)
            .field("work_product_id_digest", &work_product_id_digest)
            .field("work_product_revision", &self.work_product_revision)
            .field("credential_revision", &self.credential_revision)
            .field("page_number", &self.page_number)
            .field("page_size", &self.page_size)
            .field("cursor", &self.cursor)
            .field("window", &self.window)
            .field("secret_reference_digest", &self.secret_reference_digest)
            .finish()
    }
}

impl Serialize for NetSuiteGetRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let account_id_digest = Digest::from_text(self.account_id.as_str());
        let data_center_digest = Digest::from_text(self.data_center.as_str());
        let role_id_digest = Digest::from_text(self.role_id.as_str());
        let record_id_digest = self
            .record_id
            .as_ref()
            .map(|record_id| Digest::from_text(record_id.as_str()));
        let project_id_digest = Digest::from_text(self.project_id.as_str());
        let mission_id_digest = Digest::from_text(self.mission_id.as_str());
        let work_product_id_digest = Digest::from_text(self.work_product_id.as_str());
        let mut state = serializer.serialize_struct("NetSuiteGetRequest", 24)?;
        state.serialize_field("operation", &self.operation)?;
        state.serialize_field("endpoint", &self.endpoint)?;
        state.serialize_field("method", &self.method)?;
        state.serialize_field("accountIdDigest", &account_id_digest)?;
        state.serialize_field("dataCenterDigest", &data_center_digest)?;
        state.serialize_field("roleIdDigest", &role_id_digest)?;
        state.serialize_field("recordType", &self.record_type)?;
        state.serialize_field("recordIdDigest", &record_id_digest)?;
        state.serialize_field("collectionFilterDigest", &self.collection_filter.digest())?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("permissionDigest", &self.permission_digest)?;
        state.serialize_field("consentDigest", &self.consent_digest)?;
        state.serialize_field("projectIdDigest", &project_id_digest)?;
        state.serialize_field("projectRevision", &self.project_revision)?;
        state.serialize_field("missionIdDigest", &mission_id_digest)?;
        state.serialize_field("missionRevision", &self.mission_revision)?;
        state.serialize_field("workProductIdDigest", &work_product_id_digest)?;
        state.serialize_field("workProductRevision", &self.work_product_revision)?;
        state.serialize_field("credentialRevision", &self.credential_revision)?;
        state.serialize_field("pageNumber", &self.page_number)?;
        state.serialize_field("pageSize", &self.page_size)?;
        state.serialize_field("cursor", &self.cursor)?;
        state.serialize_field("window", &self.window)?;
        state.serialize_field("secretReferenceDigest", &self.secret_reference_digest)?;
        state.end()
    }
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
        if scope.validate_digest().is_err()
            || !operation.is_get()
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

#[derive(Clone, Eq, PartialEq)]
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

impl fmt::Debug for NetSuiteGetResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let project_id_digest = Digest::from_text(self.project_id.as_str());
        let mission_id_digest = Digest::from_text(self.mission_id.as_str());
        let work_product_id_digest = Digest::from_text(self.work_product_id.as_str());
        formatter
            .debug_struct("NetSuiteGetResponse")
            .field("operation", &self.operation)
            .field("endpoint", &self.endpoint)
            .field("payload", &self.payload)
            .field("scope_digest", &self.scope_digest)
            .field("permission_digest", &self.permission_digest)
            .field("consent_digest", &self.consent_digest)
            .field("project_id_digest", &project_id_digest)
            .field("project_revision", &self.project_revision)
            .field("mission_id_digest", &mission_id_digest)
            .field("mission_revision", &self.mission_revision)
            .field("work_product_id_digest", &work_product_id_digest)
            .field("work_product_revision", &self.work_product_revision)
            .field("credential_revision", &self.credential_revision)
            .field("status", &self.status)
            .field("response_size", &self.response_size)
            .field("provider_revision", &self.provider_revision)
            .field("next_cursor", &self.next_cursor)
            .field("response_digest", &self.response_digest)
            .finish()
    }
}

impl Serialize for NetSuiteGetResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let project_id_digest = Digest::from_text(self.project_id.as_str());
        let mission_id_digest = Digest::from_text(self.mission_id.as_str());
        let work_product_id_digest = Digest::from_text(self.work_product_id.as_str());
        let mut state = serializer.serialize_struct("NetSuiteGetResponse", 18)?;
        state.serialize_field("operation", &self.operation)?;
        state.serialize_field("endpoint", &self.endpoint)?;
        state.serialize_field("payload", &self.payload)?;
        state.serialize_field("scopeDigest", &self.scope_digest)?;
        state.serialize_field("permissionDigest", &self.permission_digest)?;
        state.serialize_field("consentDigest", &self.consent_digest)?;
        state.serialize_field("projectIdDigest", &project_id_digest)?;
        state.serialize_field("projectRevision", &self.project_revision)?;
        state.serialize_field("missionIdDigest", &mission_id_digest)?;
        state.serialize_field("missionRevision", &self.mission_revision)?;
        state.serialize_field("workProductIdDigest", &work_product_id_digest)?;
        state.serialize_field("workProductRevision", &self.work_product_revision)?;
        state.serialize_field("credentialRevision", &self.credential_revision)?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("responseSize", &self.response_size)?;
        state.serialize_field("providerRevision", &self.provider_revision)?;
        state.serialize_field("nextCursor", &self.next_cursor)?;
        state.serialize_field("responseDigest", &self.response_digest)?;
        state.end()
    }
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
        if !valid_provider_revision(&provider_revision) {
            return Err(NetSuiteTransportError::invalid_response(
                "provider revision is empty, malformed, or too long",
            ));
        }
        match &payload {
            NetSuitePayload::RecordMetadata(metadata)
                if !request.window().contains(metadata.observed_at()) =>
            {
                return Err(NetSuiteTransportError::invalid_response(
                    "record metadata timestamp is outside the observation window",
                ));
            }
            NetSuitePayload::SelectedRecord(selected)
                if !request.window().contains(selected.observed_at()) =>
            {
                return Err(NetSuiteTransportError::invalid_response(
                    "selected record timestamp is outside the observation window",
                ));
            }
            NetSuitePayload::RecordMetadata(_)
            | NetSuitePayload::RecordCollection(_)
            | NetSuitePayload::SelectedRecord(_) => {}
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
        if !valid_provider_revision(&provider_revision)
            || collection_pages.len() != collection_cursors.len()
            || scope.validate_digest().is_err()
            || metadata
                .as_ref()
                .is_some_and(|value| !scope.observation_window().contains(value.observed_at()))
            || selected_record
                .as_ref()
                .is_some_and(|value| !scope.observation_window().contains(value.observed_at()))
        {
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

pub trait NetSuiteTransport: fmt::Debug + sealed::NetSuiteTransportSealed {
    fn declared_provenance(&self) -> crate::provider::NetSuiteTransportProvenance;

    fn execute(
        &mut self,
        request: &NetSuiteGetRequest,
    ) -> Result<NetSuiteGetResponse, NetSuiteTransportError>;
}

#[derive(Clone, Debug)]
pub struct FixtureNetSuiteTransport {
    snapshot: NetSuiteSnapshot,
}

impl sealed::NetSuiteTransportSealed for FixtureNetSuiteTransport {}

impl FixtureNetSuiteTransport {
    pub fn new(snapshot: NetSuiteSnapshot) -> Self {
        Self { snapshot }
    }
}

impl NetSuiteTransport for FixtureNetSuiteTransport {
    fn declared_provenance(&self) -> crate::provider::NetSuiteTransportProvenance {
        crate::provider::NetSuiteTransportProvenance::Fixture
    }

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

impl sealed::NetSuiteTransportSealed for LoopbackNetSuiteTransport {}

impl LoopbackNetSuiteTransport {
    pub fn new(snapshot: NetSuiteSnapshot) -> Self {
        Self { snapshot }
    }
}

impl NetSuiteTransport for LoopbackNetSuiteTransport {
    fn declared_provenance(&self) -> crate::provider::NetSuiteTransportProvenance {
        crate::provider::NetSuiteTransportProvenance::Loopback
    }

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

impl sealed::NetSuiteTransportSealed for RecordingNetSuiteTransport {}

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
    fn declared_provenance(&self) -> crate::provider::NetSuiteTransportProvenance {
        crate::provider::NetSuiteTransportProvenance::Recording
    }

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

impl sealed::NetSuiteTransportSealed for BlockedEnvNetSuiteTransport {}

impl NetSuiteTransport for BlockedEnvNetSuiteTransport {
    fn declared_provenance(&self) -> crate::provider::NetSuiteTransportProvenance {
        crate::provider::NetSuiteTransportProvenance::BlockedEnv
    }

    fn execute(
        &mut self,
        _request: &NetSuiteGetRequest,
    ) -> Result<NetSuiteGetResponse, NetSuiteTransportError> {
        Err(NetSuiteTransportError::blocked_env())
    }
}

pub type NetSuiteBlockedEnvTransport = BlockedEnvNetSuiteTransport;
