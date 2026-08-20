//! Read-only AlloyDB provider and non-native transport seams.

use std::{collections::VecDeque, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{
    AlloyDbReadOperation, ClusterPosture, Digest, GcpAlloyDbClusterScope, GcpAlloyDbTarget,
    InstancePosture, MAX_RESPONSE_BYTES, ModelError, OpaquePageToken, ProviderProvenance,
    SecretReference,
};
use crate::{
    API_REVISION, GCP_ALLOYDB_API_DIGEST_INPUT, GCP_ALLOYDB_PROVIDER_ID,
    GCP_ALLOYDB_PROVIDER_VERSION, OFFICIAL_CLUSTER_GET, OFFICIAL_INSTANCE_GET, PLUGIN_VERSION,
};

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ProviderDefinitionError {
    #[error("provider definition identity drifted")]
    IdentityDrift,
    #[error("provider definition is not read-only")]
    AuthorityDrift,
    #[error(transparent)]
    Model(#[from] ModelError),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GcpAlloyDbProviderDefinition {
    pub provider_id: String,
    pub implementation: String,
    pub provider_version: String,
    pub api_revision: String,
    pub provider_digest: Digest,
    pub api_digest: Digest,
    pub read_only: bool,
    pub native: bool,
    pub connected: bool,
    pub first_party: bool,
    pub external_writes: bool,
}

impl GcpAlloyDbProviderDefinition {
    pub fn new(provider_version: impl Into<String>, api_revision: impl Into<String>) -> Self {
        let provider_version = provider_version.into();
        let api_revision = api_revision.into();
        let provider_digest = Digest::from_parts(
            "gcp-alloydb-provider/v1",
            &[
                ("provider_id", GCP_ALLOYDB_PROVIDER_ID.to_owned()),
                ("provider_version", provider_version.clone()),
                ("api_revision", api_revision.clone()),
                ("plugin_version", PLUGIN_VERSION.to_owned()),
            ],
        );
        let api_digest = Digest::from_parts(
            "gcp-alloydb-api/v1",
            &[
                ("revision", api_revision.clone()),
                ("cluster_get", OFFICIAL_CLUSTER_GET.to_owned()),
                ("instance_get", OFFICIAL_INSTANCE_GET.to_owned()),
                (
                    "operations",
                    AlloyDbReadOperation::ALL
                        .iter()
                        .map(|operation| operation.api_operation())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                ("digest_input", GCP_ALLOYDB_API_DIGEST_INPUT.to_owned()),
            ],
        );
        Self {
            provider_id: GCP_ALLOYDB_PROVIDER_ID.to_owned(),
            implementation: "GcpAlloyDbAdminProvider".to_owned(),
            provider_version,
            api_revision,
            provider_digest,
            api_digest,
            read_only: true,
            native: false,
            connected: false,
            first_party: false,
            external_writes: false,
        }
    }

    pub fn baseline() -> Self {
        Self::new(GCP_ALLOYDB_PROVIDER_VERSION, API_REVISION)
    }

    pub fn validate(&self) -> Result<(), ProviderDefinitionError> {
        if self.provider_id != GCP_ALLOYDB_PROVIDER_ID
            || self.implementation != "GcpAlloyDbAdminProvider"
            || self.provider_version != GCP_ALLOYDB_PROVIDER_VERSION
            || self.api_revision != API_REVISION
            || self.provider_digest
                != Self::new(&self.provider_version, &self.api_revision).provider_digest
            || self.api_digest != Self::new(&self.provider_version, &self.api_revision).api_digest
        {
            return Err(ProviderDefinitionError::IdentityDrift);
        }
        if !self.read_only
            || self.native
            || self.connected
            || self.first_party
            || self.external_writes
        {
            return Err(ProviderDefinitionError::AuthorityDrift);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GetClusterRequest {
    pub target: GcpAlloyDbTarget,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_digest: Digest,
    pub api_revision: String,
    #[serde(skip)]
    page_token: Option<OpaquePageToken>,
    pub request_digest: Digest,
}

impl GetClusterRequest {
    pub fn new(
        scope: &GcpAlloyDbClusterScope,
        secret: &SecretReference,
        registration_digest: &Digest,
        api_revision: impl Into<String>,
    ) -> Result<Self, ModelError> {
        let mut value = Self {
            target: scope.target.clone(),
            scope_digest: scope.digest().clone(),
            permission_digest: scope.permissions.digest().clone(),
            secret_reference_digest: secret.reference_digest().clone(),
            registration_digest: registration_digest.clone(),
            api_revision: api_revision.into(),
            page_token: None,
            request_digest: Digest::from_text("unsealed-gcp-alloydb-cluster-request"),
        };
        value.request_digest = value.compute_digest();
        Ok(value)
    }

    pub fn operation(&self) -> AlloyDbReadOperation {
        AlloyDbReadOperation::GetCluster
    }

    pub fn page_token(&self) -> Option<&OpaquePageToken> {
        self.page_token.as_ref()
    }

    pub fn digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn validate(&self) -> Result<(), ProviderError> {
        if self.page_token.is_some() || self.request_digest != self.compute_digest() {
            return Err(ProviderError::RequestDrift);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "gcp-alloydb-cluster-request/v1",
            &[
                ("target", self.target.cluster_digest().as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
                ("secret", self.secret_reference_digest.as_str().to_owned()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("api", self.api_revision.clone()),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GetInstanceRequest {
    pub target: GcpAlloyDbTarget,
    pub scope_digest: Digest,
    pub permission_digest: Digest,
    pub secret_reference_digest: Digest,
    pub registration_digest: Digest,
    pub api_revision: String,
    #[serde(skip)]
    page_token: Option<OpaquePageToken>,
    pub request_digest: Digest,
}

impl GetInstanceRequest {
    pub fn new(
        scope: &GcpAlloyDbClusterScope,
        secret: &SecretReference,
        registration_digest: &Digest,
        api_revision: impl Into<String>,
    ) -> Result<Self, ModelError> {
        let mut value = Self {
            target: scope.target.clone(),
            scope_digest: scope.digest().clone(),
            permission_digest: scope.permissions.digest().clone(),
            secret_reference_digest: secret.reference_digest().clone(),
            registration_digest: registration_digest.clone(),
            api_revision: api_revision.into(),
            page_token: None,
            request_digest: Digest::from_text("unsealed-gcp-alloydb-instance-request"),
        };
        value.request_digest = value.compute_digest();
        Ok(value)
    }

    pub fn operation(&self) -> AlloyDbReadOperation {
        AlloyDbReadOperation::GetInstance
    }

    pub fn page_token(&self) -> Option<&OpaquePageToken> {
        self.page_token.as_ref()
    }

    pub fn digest(&self) -> &Digest {
        &self.request_digest
    }

    pub fn validate(&self) -> Result<(), ProviderError> {
        if self.page_token.is_some() || self.request_digest != self.compute_digest() {
            return Err(ProviderError::RequestDrift);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "gcp-alloydb-instance-request/v1",
            &[
                ("target", self.target.instance_digest().as_str().to_owned()),
                ("scope", self.scope_digest.as_str().to_owned()),
                ("permission", self.permission_digest.as_str().to_owned()),
                ("secret", self.secret_reference_digest.as_str().to_owned()),
                ("registration", self.registration_digest.as_str().to_owned()),
                ("api", self.api_revision.clone()),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GetClusterResponse {
    pub request_digest: Digest,
    pub target: GcpAlloyDbTarget,
    pub posture: ClusterPosture,
    pub response_bytes: usize,
    pub next_page_token: Option<OpaquePageToken>,
    pub provenance: ProviderProvenance,
    pub response_digest: Digest,
}

impl GetClusterResponse {
    pub fn new(
        request: &GetClusterRequest,
        posture: ClusterPosture,
        response_bytes: usize,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderError> {
        if response_bytes > MAX_RESPONSE_BYTES {
            return Err(ProviderError::ResponseTruncated { response_bytes });
        }
        let mut value = Self {
            request_digest: request.digest().clone(),
            target: request.target.clone(),
            posture,
            response_bytes,
            next_page_token: None,
            provenance,
            response_digest: Digest::from_text("unsealed-gcp-alloydb-cluster-response"),
        };
        value.response_digest = value.compute_digest();
        Ok(value)
    }

    pub fn with_next_page_token(mut self, token: OpaquePageToken) -> Self {
        self.next_page_token = Some(token);
        self.response_digest = self.compute_digest();
        self
    }

    pub fn with_declared_digest(mut self, digest: Digest) -> Self {
        self.response_digest = digest;
        self
    }

    pub fn validate(&self) -> Result<(), ProviderError> {
        if self.response_bytes > MAX_RESPONSE_BYTES {
            return Err(ProviderError::ResponseTruncated {
                response_bytes: self.response_bytes,
            });
        }
        if self.response_digest != self.compute_digest() {
            return Err(ProviderError::ResponseTampered);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "gcp-alloydb-cluster-response/v1",
            &[
                ("request", self.request_digest.as_str().to_owned()),
                ("target", self.target.cluster_digest().as_str().to_owned()),
                ("posture", self.posture.digest().as_str().to_owned()),
                ("bytes", self.response_bytes.to_string()),
                (
                    "next_page",
                    self.next_page_token
                        .as_ref()
                        .map_or_else(String::new, |token| token.digest().as_str().to_owned()),
                ),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GetInstanceResponse {
    pub request_digest: Digest,
    pub target: GcpAlloyDbTarget,
    pub posture: InstancePosture,
    pub response_bytes: usize,
    pub next_page_token: Option<OpaquePageToken>,
    pub provenance: ProviderProvenance,
    pub response_digest: Digest,
}

impl GetInstanceResponse {
    pub fn new(
        request: &GetInstanceRequest,
        posture: InstancePosture,
        response_bytes: usize,
        provenance: ProviderProvenance,
    ) -> Result<Self, ProviderError> {
        if response_bytes > MAX_RESPONSE_BYTES {
            return Err(ProviderError::ResponseTruncated { response_bytes });
        }
        let mut value = Self {
            request_digest: request.digest().clone(),
            target: request.target.clone(),
            posture,
            response_bytes,
            next_page_token: None,
            provenance,
            response_digest: Digest::from_text("unsealed-gcp-alloydb-instance-response"),
        };
        value.response_digest = value.compute_digest();
        Ok(value)
    }

    pub fn with_next_page_token(mut self, token: OpaquePageToken) -> Self {
        self.next_page_token = Some(token);
        self.response_digest = self.compute_digest();
        self
    }

    pub fn with_declared_digest(mut self, digest: Digest) -> Self {
        self.response_digest = digest;
        self
    }

    pub fn validate(&self) -> Result<(), ProviderError> {
        if self.response_bytes > MAX_RESPONSE_BYTES {
            return Err(ProviderError::ResponseTruncated {
                response_bytes: self.response_bytes,
            });
        }
        if self.response_digest != self.compute_digest() {
            return Err(ProviderError::ResponseTampered);
        }
        Ok(())
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "gcp-alloydb-instance-response/v1",
            &[
                ("request", self.request_digest.as_str().to_owned()),
                ("target", self.target.instance_digest().as_str().to_owned()),
                ("posture", self.posture.digest().as_str().to_owned()),
                ("bytes", self.response_bytes.to_string()),
                (
                    "next_page",
                    self.next_page_token
                        .as_ref()
                        .map_or_else(String::new, |token| token.digest().as_str().to_owned()),
                ),
                ("provenance", self.provenance.as_str().to_owned()),
            ],
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderRequestReceipt {
    pub operation: AlloyDbReadOperation,
    pub request_digest: Digest,
    pub response_digest: Option<Digest>,
    pub response_bytes: Option<usize>,
    pub redacted: bool,
    pub raw_body_redacted: bool,
    pub secret_material_redacted: bool,
    pub provider_receipt: bool,
    pub receipt_digest: Digest,
}

impl ProviderRequestReceipt {
    pub fn from_response(
        operation: AlloyDbReadOperation,
        request_digest: &Digest,
        response_digest: &Digest,
        response_bytes: usize,
    ) -> Self {
        let mut value = Self {
            operation,
            request_digest: request_digest.clone(),
            response_digest: Some(response_digest.clone()),
            response_bytes: Some(response_bytes),
            redacted: true,
            raw_body_redacted: true,
            secret_material_redacted: true,
            provider_receipt: false,
            receipt_digest: Digest::from_text("unsealed-gcp-alloydb-request-receipt"),
        };
        value.receipt_digest = value.compute_digest();
        value
    }

    pub fn failure(operation: AlloyDbReadOperation, request_digest: &Digest) -> Self {
        let mut value = Self {
            operation,
            request_digest: request_digest.clone(),
            response_digest: None,
            response_bytes: None,
            redacted: true,
            raw_body_redacted: true,
            secret_material_redacted: true,
            provider_receipt: false,
            receipt_digest: Digest::from_text("unsealed-gcp-alloydb-failure-receipt"),
        };
        value.receipt_digest = value.compute_digest();
        value
    }

    pub fn validate(&self) -> bool {
        self.redacted
            && self.raw_body_redacted
            && self.secret_material_redacted
            && !self.provider_receipt
            && self.receipt_digest == self.compute_digest()
    }

    fn compute_digest(&self) -> Digest {
        Digest::from_parts(
            "gcp-alloydb-request-receipt/v1",
            &[
                ("operation", self.operation.api_operation().to_owned()),
                ("request", self.request_digest.as_str().to_owned()),
                (
                    "response",
                    self.response_digest
                        .as_ref()
                        .map_or_else(String::new, |digest| digest.as_str().to_owned()),
                ),
                (
                    "bytes",
                    self.response_bytes
                        .map_or_else(String::new, |bytes| bytes.to_string()),
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum TransportError {
    #[error("BLOCKED_ENV")]
    BlockedEnv,
    #[error("access denied")]
    AccessDenied { status_code: Option<u16> },
    #[error("resource not found")]
    NotFound { status_code: Option<u16> },
    #[error("provider request was rate limited")]
    RateLimited { status_code: Option<u16> },
    #[error("provider request timed out")]
    Timeout,
    #[error("provider returned an unavailable response")]
    Unavailable { status_code: Option<u16> },
    #[error("provider response was malformed")]
    Malformed { status_code: Option<u16> },
    #[error("provider response body was truncated")]
    Truncated { response_bytes: usize },
    #[error("provider returned a pagination continuation")]
    Pagination { token_digest: Digest },
    #[error("provider response is unknown")]
    Unknown { reason_digest: Digest },
    #[error("provider response contained a redacted raw body")]
    RawBody {
        status_code: Option<u16>,
        body_digest: Digest,
    },
}

impl TransportError {
    /// Hashes and discards a raw body so transport adapters cannot accidentally
    /// put provider payloads into a Layer-1 error or receipt.
    pub fn from_raw_body(status_code: Option<u16>, raw_body: impl AsRef<[u8]>) -> Self {
        Self::RawBody {
            status_code,
            body_digest: Digest::from_bytes(raw_body.as_ref()),
        }
    }

    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::AccessDenied { status_code }
            | Self::NotFound { status_code }
            | Self::RateLimited { status_code }
            | Self::Unavailable { status_code }
            | Self::Malformed { status_code }
            | Self::RawBody { status_code, .. } => *status_code,
            Self::BlockedEnv
            | Self::Timeout
            | Self::Truncated { .. }
            | Self::Pagination { .. }
            | Self::Unknown { .. } => None,
        }
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ProviderError {
    #[error("provider definition drifted")]
    DefinitionDrift,
    #[error("provider request drifted")]
    RequestDrift,
    #[error("provider response was tampered")]
    ResponseTampered,
    #[error("provider response exceeded the bounded response size")]
    ResponseTruncated { response_bytes: usize },
    #[error("provider response carried an unexpected pagination continuation")]
    PaginationLoop { token_digest: Digest },
    #[error("provider provenance was not an allowed non-native provenance")]
    ProvenanceDrift,
    #[error(transparent)]
    Transport(TransportError),
    #[error(transparent)]
    Model(#[from] ModelError),
}

impl ProviderError {
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::Transport(error) => error.status_code(),
            Self::ResponseTruncated { .. }
            | Self::PaginationLoop { .. }
            | Self::DefinitionDrift
            | Self::RequestDrift
            | Self::ResponseTampered
            | Self::ProvenanceDrift
            | Self::Model(_) => None,
        }
    }
}

pub trait GcpAlloyDbTransport: fmt::Debug {
    fn provenance(&self) -> ProviderProvenance;

    fn get_cluster(
        &mut self,
        request: &GetClusterRequest,
    ) -> Result<GetClusterResponse, TransportError>;

    fn get_instance(
        &mut self,
        request: &GetInstanceRequest,
    ) -> Result<GetInstanceResponse, TransportError>;
}

pub struct GcpAlloyDbAdminProvider<T> {
    transport: T,
    definition: GcpAlloyDbProviderDefinition,
}

impl<T: fmt::Debug> fmt::Debug for GcpAlloyDbAdminProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GcpAlloyDbAdminProvider")
            .field("definition", &self.definition)
            .field("transport", &self.transport)
            .finish()
    }
}

impl<T: GcpAlloyDbTransport> GcpAlloyDbAdminProvider<T> {
    pub fn new(transport: T) -> Result<Self, ProviderDefinitionError> {
        Self::with_definition(transport, GcpAlloyDbProviderDefinition::baseline())
    }

    pub fn with_identity(
        transport: T,
        provider_version: impl Into<String>,
        api_revision: impl Into<String>,
    ) -> Result<Self, ProviderDefinitionError> {
        Self::with_definition(
            transport,
            GcpAlloyDbProviderDefinition::new(provider_version, api_revision),
        )
    }

    pub fn with_definition(
        transport: T,
        definition: GcpAlloyDbProviderDefinition,
    ) -> Result<Self, ProviderDefinitionError> {
        definition.validate()?;
        Ok(Self {
            transport,
            definition,
        })
    }

    pub fn definition(&self) -> &GcpAlloyDbProviderDefinition {
        &self.definition
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn get_cluster(
        &mut self,
        request: &GetClusterRequest,
    ) -> Result<GetClusterResponse, ProviderError> {
        request.validate()?;
        if request.api_revision != self.definition.api_revision {
            return Err(ProviderError::DefinitionDrift);
        }
        let response = self
            .transport
            .get_cluster(request)
            .map_err(ProviderError::Transport)?;
        self.validate_cluster_response(request, response)
    }

    pub fn get_instance(
        &mut self,
        request: &GetInstanceRequest,
    ) -> Result<GetInstanceResponse, ProviderError> {
        request.validate()?;
        if request.api_revision != self.definition.api_revision {
            return Err(ProviderError::DefinitionDrift);
        }
        let response = self
            .transport
            .get_instance(request)
            .map_err(ProviderError::Transport)?;
        self.validate_instance_response(request, response)
    }

    fn validate_cluster_response(
        &self,
        request: &GetClusterRequest,
        response: GetClusterResponse,
    ) -> Result<GetClusterResponse, ProviderError> {
        if response.request_digest != *request.digest() {
            return Err(ProviderError::RequestDrift);
        }
        if response.provenance != self.transport.provenance()
            || response.provenance.connected()
            || response.provenance.native()
            || response.provenance.first_party()
        {
            return Err(ProviderError::ProvenanceDrift);
        }
        response.validate()?;
        Ok(response)
    }

    fn validate_instance_response(
        &self,
        request: &GetInstanceRequest,
        response: GetInstanceResponse,
    ) -> Result<GetInstanceResponse, ProviderError> {
        if response.request_digest != *request.digest() {
            return Err(ProviderError::RequestDrift);
        }
        if response.provenance != self.transport.provenance()
            || response.provenance.connected()
            || response.provenance.native()
            || response.provenance.first_party()
        {
            return Err(ProviderError::ProvenanceDrift);
        }
        response.validate()?;
        Ok(response)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransportCall {
    pub operation: AlloyDbReadOperation,
    pub request_digest: Digest,
}

#[derive(Clone, Debug, Default)]
struct ResponseQueue {
    cluster: VecDeque<Result<GetClusterResponse, TransportError>>,
    instance: VecDeque<Result<GetInstanceResponse, TransportError>>,
}

impl ResponseQueue {
    fn cluster(&mut self) -> Result<GetClusterResponse, TransportError> {
        self.cluster.pop_front().unwrap_or_else(|| {
            Err(TransportError::Unknown {
                reason_digest: Digest::from_text("cluster fixture response unavailable"),
            })
        })
    }

    fn instance(&mut self) -> Result<GetInstanceResponse, TransportError> {
        self.instance.pop_front().unwrap_or_else(|| {
            Err(TransportError::Unknown {
                reason_digest: Digest::from_text("instance fixture response unavailable"),
            })
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct FixtureGcpAlloyDbTransport {
    queue: ResponseQueue,
}

impl FixtureGcpAlloyDbTransport {
    pub fn new(
        cluster: Result<GetClusterResponse, TransportError>,
        instance: Result<GetInstanceResponse, TransportError>,
    ) -> Self {
        let mut value = Self::default();
        value.push_cluster_response(cluster);
        value.push_instance_response(instance);
        value
    }

    pub fn push_cluster_response(&mut self, response: Result<GetClusterResponse, TransportError>) {
        self.queue.cluster.push_back(response);
    }

    pub fn push_instance_response(
        &mut self,
        response: Result<GetInstanceResponse, TransportError>,
    ) {
        self.queue.instance.push_back(response);
    }
}

impl GcpAlloyDbTransport for FixtureGcpAlloyDbTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Fixture
    }

    fn get_cluster(
        &mut self,
        _request: &GetClusterRequest,
    ) -> Result<GetClusterResponse, TransportError> {
        self.queue.cluster()
    }

    fn get_instance(
        &mut self,
        _request: &GetInstanceRequest,
    ) -> Result<GetInstanceResponse, TransportError> {
        self.queue.instance()
    }
}

#[derive(Clone, Debug, Default)]
pub struct RecordingGcpAlloyDbTransport {
    queue: ResponseQueue,
    calls: Vec<TransportCall>,
}

impl RecordingGcpAlloyDbTransport {
    pub fn new(
        cluster: Result<GetClusterResponse, TransportError>,
        instance: Result<GetInstanceResponse, TransportError>,
    ) -> Self {
        let mut value = Self::default();
        value.push_cluster_response(cluster);
        value.push_instance_response(instance);
        value
    }

    pub fn push_cluster_response(&mut self, response: Result<GetClusterResponse, TransportError>) {
        self.queue.cluster.push_back(response);
    }

    pub fn push_instance_response(
        &mut self,
        response: Result<GetInstanceResponse, TransportError>,
    ) {
        self.queue.instance.push_back(response);
    }

    pub fn calls(&self) -> &[TransportCall] {
        &self.calls
    }
}

impl GcpAlloyDbTransport for RecordingGcpAlloyDbTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Recording
    }

    fn get_cluster(
        &mut self,
        request: &GetClusterRequest,
    ) -> Result<GetClusterResponse, TransportError> {
        self.calls.push(TransportCall {
            operation: AlloyDbReadOperation::GetCluster,
            request_digest: request.digest().clone(),
        });
        self.queue.cluster()
    }

    fn get_instance(
        &mut self,
        request: &GetInstanceRequest,
    ) -> Result<GetInstanceResponse, TransportError> {
        self.calls.push(TransportCall {
            operation: AlloyDbReadOperation::GetInstance,
            request_digest: request.digest().clone(),
        });
        self.queue.instance()
    }
}

#[derive(Clone, Debug, Default)]
pub struct FakeGcpAlloyDbTransport {
    queue: ResponseQueue,
}

impl FakeGcpAlloyDbTransport {
    pub fn new(
        cluster: Result<GetClusterResponse, TransportError>,
        instance: Result<GetInstanceResponse, TransportError>,
    ) -> Self {
        let mut value = Self::default();
        value.push_cluster_response(cluster);
        value.push_instance_response(instance);
        value
    }

    pub fn push_cluster_response(&mut self, response: Result<GetClusterResponse, TransportError>) {
        self.queue.cluster.push_back(response);
    }

    pub fn push_instance_response(
        &mut self,
        response: Result<GetInstanceResponse, TransportError>,
    ) {
        self.queue.instance.push_back(response);
    }
}

impl GcpAlloyDbTransport for FakeGcpAlloyDbTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Fake
    }

    fn get_cluster(
        &mut self,
        _request: &GetClusterRequest,
    ) -> Result<GetClusterResponse, TransportError> {
        self.queue.cluster()
    }

    fn get_instance(
        &mut self,
        _request: &GetInstanceRequest,
    ) -> Result<GetInstanceResponse, TransportError> {
        self.queue.instance()
    }
}

#[derive(Clone, Debug, Default)]
pub struct LoopbackGcpAlloyDbTransport {
    queue: ResponseQueue,
}

impl LoopbackGcpAlloyDbTransport {
    pub fn new(
        cluster: Result<GetClusterResponse, TransportError>,
        instance: Result<GetInstanceResponse, TransportError>,
    ) -> Self {
        let mut value = Self::default();
        value.push_cluster_response(cluster);
        value.push_instance_response(instance);
        value
    }

    pub fn push_cluster_response(&mut self, response: Result<GetClusterResponse, TransportError>) {
        self.queue.cluster.push_back(response);
    }

    pub fn push_instance_response(
        &mut self,
        response: Result<GetInstanceResponse, TransportError>,
    ) {
        self.queue.instance.push_back(response);
    }
}

impl GcpAlloyDbTransport for LoopbackGcpAlloyDbTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::Loopback
    }

    fn get_cluster(
        &mut self,
        _request: &GetClusterRequest,
    ) -> Result<GetClusterResponse, TransportError> {
        self.queue.cluster()
    }

    fn get_instance(
        &mut self,
        _request: &GetInstanceRequest,
    ) -> Result<GetInstanceResponse, TransportError> {
        self.queue.instance()
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BlockedEnvTransport;

impl GcpAlloyDbTransport for BlockedEnvTransport {
    fn provenance(&self) -> ProviderProvenance {
        ProviderProvenance::BlockedEnv
    }

    fn get_cluster(
        &mut self,
        _request: &GetClusterRequest,
    ) -> Result<GetClusterResponse, TransportError> {
        Err(TransportError::BlockedEnv)
    }

    fn get_instance(
        &mut self,
        _request: &GetInstanceRequest,
    ) -> Result<GetInstanceResponse, TransportError> {
        Err(TransportError::BlockedEnv)
    }
}

// Convenient aliases mirror the names commonly used by standalone plugin
// callers while keeping the explicit GCP type names available.
pub type FixtureTransport = FixtureGcpAlloyDbTransport;
pub type RecordingTransport = RecordingGcpAlloyDbTransport;
pub type FakeTransport = FakeGcpAlloyDbTransport;
pub type LoopbackTransport = LoopbackGcpAlloyDbTransport;
