//! Layer-1 SuiteTalk provider definition and bounded response validation.

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    NETSUITE_ACCOUNTING_RESULT_SCHEMA_VERSION, NETSUITE_PROVIDER_ID,
    model::{
        Digest, ModelError, NetSuiteBounds, NetSuitePayload, NetSuiteReadOperation,
        NetSuiteRecordType, Revision,
    },
    transport::{
        NetSuiteGetRequest, NetSuiteGetResponse, NetSuiteHttpMethod, NetSuiteSuiteTalkEndpoint,
        NetSuiteTransport, NetSuiteTransportError, NetSuiteTransportErrorKind,
    },
};

pub type NetSuiteProviderRevision = String;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetSuiteTransportProvenance {
    Fixture,
    Recording,
    Loopback,
    #[serde(rename = "BLOCKED_ENV")]
    BlockedEnv,
}

impl NetSuiteTransportProvenance {
    pub const fn is_native(self) -> bool {
        false
    }

    pub const fn is_connected(self) -> bool {
        false
    }

    pub const fn is_blocked_env(self) -> bool {
        matches!(self, Self::BlockedEnv)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("NetSuite provider version is empty or malformed")]
    EmptyVersion,
    #[error("Layer 1 cannot register a native or Connected NetSuite provider")]
    NativeProviderForbidden,
    #[error("transport provenance does not match the provider claim")]
    ProvenanceMismatch,
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetSuiteProviderDefinition {
    schema_version: String,
    provider_id: String,
    provider_version: String,
    capability_digest: Digest,
    provenance: NetSuiteTransportProvenance,
    operations: Vec<NetSuiteReadOperation>,
    native: bool,
    connected: bool,
    live_execution: bool,
}

impl NetSuiteProviderDefinition {
    pub fn new(
        provider_version: impl Into<String>,
        provenance: NetSuiteTransportProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        let provider_version = provider_version.into();
        if provider_version.is_empty() || provider_version.len() > 128 {
            return Err(ProviderDefinitionError::EmptyVersion);
        }
        if provenance.is_native() || provenance.is_connected() {
            return Err(ProviderDefinitionError::NativeProviderForbidden);
        }
        let operations = vec![
            NetSuiteReadOperation::RecordMetadata,
            NetSuiteReadOperation::RecordCollectionFilter,
            NetSuiteReadOperation::SelectedRecord,
            NetSuiteReadOperation::SuiteQlProposal,
        ];
        let capability_digest = Digest::from_fields(
            "netsuite-suitetalk-capability/v1",
            &[
                NETSUITE_ACCOUNTING_RESULT_SCHEMA_VERSION.to_owned(),
                NETSUITE_PROVIDER_ID.to_owned(),
                provider_version.clone(),
                format!("{provenance:?}"),
                operations
                    .iter()
                    .map(|operation| operation.contract_name().to_owned())
                    .collect::<Vec<_>>()
                    .join(","),
                "GET-only-record-seams;parameterized-suiteql-proposal-only".to_owned(),
                "native=false".to_owned(),
                "connected=false".to_owned(),
            ],
        );
        Ok(Self {
            schema_version: NETSUITE_ACCOUNTING_RESULT_SCHEMA_VERSION.to_owned(),
            provider_id: NETSUITE_PROVIDER_ID.to_owned(),
            provider_version,
            capability_digest,
            provenance,
            operations,
            native: false,
            connected: false,
            live_execution: false,
        })
    }

    pub fn provider_digest(&self) -> Digest {
        Digest::from_fields(
            "netsuite-provider-definition/v1",
            &[
                self.schema_version.clone(),
                self.provider_id.clone(),
                self.provider_version.clone(),
                self.capability_digest.as_str().to_owned(),
                format!("{:?}", self.provenance),
                self.operations
                    .iter()
                    .map(|operation| operation.contract_name().to_owned())
                    .collect::<Vec<_>>()
                    .join(","),
                self.native.to_string(),
                self.connected.to_string(),
                self.live_execution.to_string(),
            ],
        )
    }

    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn provider_version(&self) -> &str {
        &self.provider_version
    }

    pub fn capability_digest(&self) -> &Digest {
        &self.capability_digest
    }

    pub const fn provenance(&self) -> NetSuiteTransportProvenance {
        self.provenance
    }

    pub fn operations(&self) -> &[NetSuiteReadOperation] {
        &self.operations
    }

    pub const fn is_native(&self) -> bool {
        self.native
    }

    pub const fn is_connected(&self) -> bool {
        self.connected
    }

    pub const fn live_execution(&self) -> bool {
        self.live_execution
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetSuiteEndpointKind {
    RecordMetadata,
    RecordCollection,
    SelectedRecord,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetSuiteEndpointIdentity {
    pub kind: NetSuiteEndpointKind,
    pub record_type: NetSuiteRecordType,
    pub record_id_digest: Option<Digest>,
    pub endpoint_digest: Digest,
}

impl NetSuiteEndpointIdentity {
    fn from_endpoint(endpoint: &NetSuiteSuiteTalkEndpoint) -> Self {
        let (kind, record_type, record_id_digest) = match endpoint {
            NetSuiteSuiteTalkEndpoint::RecordMetadata { record_type } => {
                (NetSuiteEndpointKind::RecordMetadata, *record_type, None)
            }
            NetSuiteSuiteTalkEndpoint::RecordCollection { record_type } => {
                (NetSuiteEndpointKind::RecordCollection, *record_type, None)
            }
            NetSuiteSuiteTalkEndpoint::SelectedRecord {
                record_type,
                record_id,
            } => (
                NetSuiteEndpointKind::SelectedRecord,
                *record_type,
                Some(Digest::from_text(record_id.as_str())),
            ),
        };
        Self {
            kind,
            record_type,
            record_id_digest,
            endpoint_digest: Digest::from_text(endpoint.path()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetSuiteReadReceipt {
    pub operation: NetSuiteReadOperation,
    pub endpoint_identity: NetSuiteEndpointIdentity,
    pub method: NetSuiteHttpMethod,
    pub request_digest: Digest,
    pub response_status: u16,
    pub response_size: usize,
    pub response_digest: Digest,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub consent_digest: Digest,
    pub credential_revision: Revision,
    pub provider_revision: String,
    pub attempts: u8,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetSuiteRetryEvidence {
    pub operation: NetSuiteReadOperation,
    pub attempt: u8,
    pub kind: NetSuiteTransportErrorKind,
    pub status_code: Option<u16>,
    pub diagnostic_digest: Digest,
    pub backoff_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetSuiteReadFailure {
    pub operation: NetSuiteReadOperation,
    pub kind: NetSuiteTransportErrorKind,
    pub status_code: Option<u16>,
    pub diagnostic_digest: Digest,
    pub provenance: NetSuiteTransportProvenance,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum NetSuiteProviderError {
    #[error("NetSuite request is invalid: {0}")]
    Request(String),
    #[error("NetSuite transport failed: {0}")]
    Transport(#[source] NetSuiteTransportError),
    #[error("NetSuite response exceeded the safe response bound: {size} bytes")]
    ResponseTooLarge { size: usize },
    #[error("NetSuite response integrity validation failed")]
    ResponseIntegrity,
    #[error("NetSuite response operation or endpoint does not match the request")]
    OperationMismatch,
    #[error("NetSuite response scope or permission fence does not match the request")]
    ScopeMismatch,
    #[error("NetSuite response revision or credential fence does not match the request")]
    RevisionMismatch,
    #[error("NetSuite returned unexpected HTTP status {status}")]
    UnexpectedStatus { status: u16 },
    #[error("NetSuite response payload is not the typed shape for the requested read")]
    InvalidPayload,
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetSuiteProviderRead {
    pub response: NetSuiteGetResponse,
    pub receipt: NetSuiteReadReceipt,
    pub retries: Vec<NetSuiteRetryEvidence>,
}

pub struct NetSuiteSuiteTalkProvider<T> {
    transport: T,
    definition: NetSuiteProviderDefinition,
}

impl<T: fmt::Debug> fmt::Debug for NetSuiteSuiteTalkProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NetSuiteSuiteTalkProvider")
            .field("definition", &self.definition)
            .field("transport", &self.transport)
            .finish()
    }
}

impl<T: NetSuiteTransport> NetSuiteSuiteTalkProvider<T> {
    pub fn new(
        transport: T,
        provider_version: impl Into<String>,
        provenance: NetSuiteTransportProvenance,
    ) -> Result<Self, ProviderDefinitionError> {
        if transport.declared_provenance() != provenance {
            return Err(ProviderDefinitionError::ProvenanceMismatch);
        }
        let definition = NetSuiteProviderDefinition::new(provider_version, provenance)?;
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn definition(&self) -> &NetSuiteProviderDefinition {
        &self.definition
    }

    pub fn definition_digest(&self) -> Digest {
        self.definition.provider_digest()
    }

    pub const fn is_native(&self) -> bool {
        false
    }

    pub const fn is_connected(&self) -> bool {
        false
    }

    pub fn provenance(&self) -> NetSuiteTransportProvenance {
        self.definition.provenance()
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn read(
        &mut self,
        request: &NetSuiteGetRequest,
        bounds: NetSuiteBounds,
    ) -> Result<NetSuiteProviderRead, NetSuiteProviderError> {
        if !request.operation().is_get()
            || request.method() != NetSuiteHttpMethod::Get
            || request.page_number() == 0
            || request.page_number() > bounds.max_pages()
            || request.page_size() > bounds.page_size()
            || !self.definition.operations().contains(&request.operation())
        {
            return Err(NetSuiteProviderError::Request(
                "only bounded allowlisted GET requests are accepted".to_owned(),
            ));
        }
        let expected_endpoint = match (request.operation(), request.record_id()) {
            (NetSuiteReadOperation::RecordMetadata, _) => {
                NetSuiteSuiteTalkEndpoint::RecordMetadata {
                    record_type: request.record_type(),
                }
            }
            (NetSuiteReadOperation::RecordCollectionFilter, _) => {
                NetSuiteSuiteTalkEndpoint::RecordCollection {
                    record_type: request.record_type(),
                }
            }
            (NetSuiteReadOperation::SelectedRecord, Some(record_id)) => {
                NetSuiteSuiteTalkEndpoint::SelectedRecord {
                    record_type: request.record_type(),
                    record_id: record_id.clone(),
                }
            }
            (NetSuiteReadOperation::SelectedRecord, None) => {
                return Err(NetSuiteProviderError::Request(
                    "selected record GET requires a scoped record id".to_owned(),
                ));
            }
            (NetSuiteReadOperation::SuiteQlProposal, _) => {
                return Err(NetSuiteProviderError::Request(
                    "SuiteQL proposals are never sent to the GET transport".to_owned(),
                ));
            }
        };
        if request.endpoint() != &expected_endpoint {
            return Err(NetSuiteProviderError::Request(
                "endpoint is not generated from the allowlisted operation".to_owned(),
            ));
        }
        let mut retries = Vec::new();
        let mut attempts = 0_u8;
        loop {
            attempts = attempts.saturating_add(1);
            match self.transport.execute(request) {
                Ok(response) => {
                    Self::validate_response(
                        request,
                        &bounds,
                        &response,
                        self.definition.provider_version(),
                    )?;
                    let receipt = NetSuiteReadReceipt {
                        operation: request.operation(),
                        endpoint_identity: NetSuiteEndpointIdentity::from_endpoint(
                            request.endpoint(),
                        ),
                        method: request.method(),
                        request_digest: request.request_digest()?,
                        response_status: response.status(),
                        response_size: response.response_size(),
                        response_digest: response.response_digest().clone(),
                        scope_digest: response.scope_digest().clone(),
                        permission_digest: response.permission_digest().clone(),
                        consent_digest: response.consent_digest().clone(),
                        credential_revision: response.credential_revision(),
                        provider_revision: response.provider_revision().to_owned(),
                        attempts,
                    };
                    return Ok(NetSuiteProviderRead {
                        response,
                        receipt,
                        retries,
                    });
                }
                Err(error) if error.is_retryable() && attempts < bounds.max_retry_attempts() => {
                    retries.push(NetSuiteRetryEvidence {
                        operation: request.operation(),
                        attempt: attempts,
                        kind: error.kind(),
                        status_code: error.status_code(),
                        diagnostic_digest: error.diagnostic_digest().clone(),
                        backoff_ms: bounded_backoff_ms(attempts),
                    });
                }
                Err(error) => return Err(NetSuiteProviderError::Transport(error)),
            }
        }
    }

    fn validate_response(
        request: &NetSuiteGetRequest,
        bounds: &NetSuiteBounds,
        response: &NetSuiteGetResponse,
        provider_revision: &str,
    ) -> Result<(), NetSuiteProviderError> {
        response
            .validate_integrity()
            .map_err(|_| NetSuiteProviderError::ResponseIntegrity)?;
        if response.operation() != request.operation() || response.endpoint() != request.endpoint()
        {
            return Err(NetSuiteProviderError::OperationMismatch);
        }
        if response.scope_digest() != request.scope_digest()
            || response.permission_digest() != request.permission_digest()
            || response.consent_digest() != request.consent_digest()
        {
            return Err(NetSuiteProviderError::ScopeMismatch);
        }
        if response.provider_revision() != provider_revision {
            return Err(NetSuiteProviderError::RevisionMismatch);
        }
        if request
            .collection_filter()
            .validate_for_window(request.window())
            .is_err()
        {
            return Err(NetSuiteProviderError::ScopeMismatch);
        }
        if response.project_id() != request.project_id()
            || response.mission_id() != request.mission_id()
            || response.work_product_id() != request.work_product_id()
        {
            return Err(NetSuiteProviderError::ScopeMismatch);
        }
        if response.project_revision() != request.project_revision()
            || response.mission_revision() != request.mission_revision()
            || response.work_product_revision() != request.work_product_revision()
            || response.credential_revision() != request.credential_revision()
        {
            return Err(NetSuiteProviderError::RevisionMismatch);
        }
        if !(200..=299).contains(&response.status()) {
            return Err(NetSuiteProviderError::UnexpectedStatus {
                status: response.status(),
            });
        }
        if response.response_size() > bounds.max_response_bytes() {
            return Err(NetSuiteProviderError::ResponseTooLarge {
                size: response.response_size(),
            });
        }
        match (request.operation(), response.payload()) {
            (NetSuiteReadOperation::RecordMetadata, NetSuitePayload::RecordMetadata(metadata))
                if metadata.record_type() == request.record_type()
                    && request.window().contains(metadata.observed_at()) =>
            {
                metadata
                    .validate_digest()
                    .map_err(NetSuiteProviderError::Model)
            }
            (
                NetSuiteReadOperation::RecordCollectionFilter,
                NetSuitePayload::RecordCollection(collection),
            ) if collection.record_type() == request.record_type()
                && collection.page_number() == request.page_number() =>
            {
                collection
                    .validate_digest()
                    .map_err(NetSuiteProviderError::Model)?;
                if collection.has_more() && response.next_cursor().is_none() {
                    return Err(NetSuiteProviderError::InvalidPayload);
                }
                Ok(())
            }
            (NetSuiteReadOperation::SelectedRecord, NetSuitePayload::SelectedRecord(selected))
                if selected.record_type() == request.record_type()
                    && request.window().contains(selected.observed_at())
                    && request.record_id().is_some_and(|record_id| {
                        selected.record_id_digest() == &Digest::from_text(record_id.as_str())
                    }) =>
            {
                selected
                    .validate_digest()
                    .map_err(NetSuiteProviderError::Model)
            }
            _ => Err(NetSuiteProviderError::InvalidPayload),
        }
    }
}

fn bounded_backoff_ms(attempt: u8) -> u64 {
    match attempt {
        1 => 50,
        2 => 100,
        3 => 200,
        _ => 400,
    }
}
